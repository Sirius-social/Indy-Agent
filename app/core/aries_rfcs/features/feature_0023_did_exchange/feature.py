import re
import json
import uuid
import base64

from core.base import MessageFeature, FeatureMeta, WriteOnlyChannel, ReadOnlyChannel
from core.messages.did_doc import DIDDoc
from core.messages.message import Message
from core.serializer.json_serializer import JSONSerializer as Serializer
from core.wallet import WalletAgent, InvokableStateMachineMeta
from state_machines.base import BaseStateMachine
from .errors import *
from .statuses import *


class DIDExchange(MessageFeature, metaclass=FeatureMeta):
    """https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange"""

    FAMILY_NAME = "didexchange"
    VERSION = "1.0"
    FAMILY = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/" + FAMILY_NAME + "/" + VERSION

    CONNECTION = 'connection'
    INVITE = FAMILY + "/invitation"
    REQUEST = FAMILY + "/request"
    RESPONSE = FAMILY + "/response"
    REQUEST_NOT_ACCEPTED = "request_not_accepted"
    # Problem codes
    # No corresponding connection request found
    RESPONSE_FOR_UNKNOWN_REQUEST = "response_for_unknown_request"
    # Verkey provided in response does not match expected key
    KEY_ERROR = "verkey_error"
    # internal usage definitions
    MESSAGE_CONTENT_TYPE = 'application/json'

    @classmethod
    def endorsement(cls, msg: Message) -> bool:
        matches = re.match("(.+/.+/\d+.\d+).+", msg.type)
        if matches:
            family = matches.group(1)
            return family in cls.FAMILY
        return False

    async def handle(self, msg: Message) -> Message:
        pass

    @classmethod
    async def generate_invite_message(cls, label: str, endpoint: str, agent_name: str, pass_phrase: str) -> Message:
        """ Generate new connection invitation.

            This interaction represents an out-of-band communication channel. In the future and in
            practice, these sort of invitations will be received over any number of channels such as
            SMS, Email, QR Code, NFC, etc.

            Structure of an invite message:

                {
                    "@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/invitation",
                    "label": "Alice",
                    "did": "did:sov:QmWbsNYhMrjHiqZDTUTEJs"
                }

            Or, in the case of a peer DID:

                {
                    "@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/invitation",
                    "label": "Alice",
                    "did": "did:peer:oiSqsNYhMrjHiqZDTUthsw",
                    "key": "8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K",
                    "endpoint": "https://example.com/endpoint"
                }

            Currently, only peer DID is supported.
        """
        await WalletAgent.ensure_agent_is_open(agent_name, pass_phrase)
        connection_key = await WalletAgent.create_key(agent_name, pass_phrase)
        # Store connection key
        await WalletAgent.add_wallet_record(agent_name, pass_phrase, 'connection_key', connection_key, connection_key)
        invite_msg = Message({
            '@type': cls.INVITE,
            'label': label,
            'recipientKeys': [connection_key],
            'serviceEndpoint': endpoint,
            # routingKeys not specified, but here is where they would be put in the invite.
        })
        return invite_msg

    @classmethod
    async def generate_invite_link(cls, label: str, endpoint: str, agent_name: str, pass_phrase: str):
        invite_msg = await cls.generate_invite_message(label, endpoint, agent_name, pass_phrase)
        b64_invite = base64.urlsafe_b64encode(Serializer.serialize(invite_msg)).decode('ascii')
        return '?c_i=' + b64_invite, invite_msg

    @classmethod
    async def receive_invite_message(cls, msg: Message, agent_name: str, pass_phrase: str) -> None:
        """ Receive and save invite.

            This interaction represents an out-of-band communication channel. In the future and in
            practice, these sort of invitations will be received over any number of channels such as
            SMS, Email, QR Code, NFC, etc.

            In this iteration, invite messages are received from the admin interface as a URL
            after being copied and pasted from another agent instance.

            The URL is formatted as follows:

                https://<domain>/<path>?c_i=<invitationstring>

            The invitation string is a base64 url encoded json string.

            Structure of an invite message:

                {
                    "@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/invitation",
                    "label": "Alice",
                    "did": "did:sov:QmWbsNYhMrjHiqZDTUTEJs"
                }

            Or, in the case of a peer DID:

                {
                    "@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/invitation",
                    "label": "Alice",
                    "key": "8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K",
                    "endpoint": "https://example.com/endpoint"
                }

            Currently, only peer DID format is supported.
        """
        await WalletAgent.add_wallet_record(
            agent_name,
            pass_phrase,
            'invitations',
            msg['recipientKeys'][0],
            Serializer.serialize(msg).decode('utf-8')
        )

    @classmethod
    async def receive_invite_link(cls, link: str, agent_name: str, pass_phrase: str):
        await WalletAgent.ensure_agent_is_open(agent_name, pass_phrase)
        matches = re.match("(.+)?c_i=(.+)", link)
        if not matches:
            raise BadInviteException("Invite string is improperly formatted")
        invite_msg = Serializer.deserialize(
            base64.urlsafe_b64decode(matches.group(2)).decode('utf-8')
        )
        if cls.endorsement(invite_msg):
            cls.receive_invite_message(invite_msg, agent_name, pass_phrase)
        else:
            return False

    class Invite:
        @staticmethod
        def parse(invite_url: str) -> Message:
            matches = re.match('(.+)?c_i=(.+)', invite_url)
            assert matches, 'Improperly formatted invite url!'

            invite_msg = Serializer.deserialize(
                base64.urlsafe_b64decode(matches.group(2)).decode('ascii')
            )

            invite_msg.check_for_attrs(
                [
                    ('@type', DIDExchange.INVITE),
                    'label',
                    'recipientKeys',
                    'serviceEndpoint'
                ]
            )

            return invite_msg

        @staticmethod
        def build(label: str, connection_key: str, endpoint: str) -> str:
            msg = Message({
                '@type': DIDExchange.INVITE,
                'label': label,
                'recipientKeys': [connection_key],
                'serviceEndpoint': endpoint,
                # routing_keys not specified, but here is where they would be put in the invite.
            })

            b64_invite = base64.urlsafe_b64encode(
                bytes(
                    Serializer.serialize(msg).decode('utf-8'),
                    'ascii'
                )
            ).decode('ascii')

            return '{}?c_i={}'.format(endpoint, b64_invite)

    class Request:
        @staticmethod
        def parse(request: Message):
            return (
                request[DIDExchange.CONNECTION][DIDDoc.DID_DOC]['publicKey'][0]['controller'],
                request[DIDExchange.CONNECTION][DIDDoc.DID_DOC]['publicKey'][0]['publicKeyBase58'],
                request[DIDExchange.CONNECTION][DIDDoc.DID_DOC]['service'][0]['serviceEndpoint']
            )

        @staticmethod
        def build(label: str, my_did: str, my_vk: str, endpoint: str) -> Message:
            return Message({
                '@type': DIDExchange.REQUEST,
                '@id': str(uuid.uuid4()),
                'label': label,
                'connection': {
                    'did': my_did,
                    'did_doc': {
                        "@context": "https://w3id.org/did/v1",
                        "id": my_did,
                        "publicKey": [{
                            "id": my_did + "#keys-1",
                            "type": "Ed25519VerificationKey2018",
                            "controller": my_did,
                            "publicKeyBase58": my_vk
                        }],
                        "service": [{
                            "id": my_did + ";indy",
                            "type": "IndyAgent",
                            "recipientKeys": [my_vk],
                            # "routingKeys": ["<example-agency-verkey>"],
                            "serviceEndpoint": endpoint,
                        }],
                    }
                }
            })

        @staticmethod
        def validate(request):
            request.check_for_attrs(
                [
                    ('@type', DIDExchange.REQUEST),
                    '@id',
                    'label',
                    DIDExchange.CONNECTION
                ]
            )

            Message.check_for_attrs_in_message(
                [
                    DIDDoc.DID,
                    DIDDoc.DID_DOC
                ],
                request[DIDExchange.CONNECTION]
            )

            DIDDoc.validate(request[DIDExchange.CONNECTION][DIDDoc.DID_DOC])

    class Response:
        @staticmethod
        def build(req_id: str, my_did: str, my_vk: str, endpoint: str) -> Message:
            return Message({
                '@type': DIDExchange.RESPONSE,
                '@id': str(uuid.uuid4()),
                '~thread': {Message.THREAD_ID: req_id, Message.SENDER_ORDER: 0},
                'connection': {
                    'did': my_did,
                    'did_doc': {
                        "@context": "https://w3id.org/did/v1",
                        "id": my_did,
                        "publicKey": [{
                            "id": my_did + "#keys-1",
                            "type": "Ed25519VerificationKey2018",
                            "controller": my_did,
                            "publicKeyBase58": my_vk
                        }],
                        "service": [{
                            "id": my_did + ";indy",
                            "type": "IndyAgent",
                            "recipientKeys": [my_vk],
                            # "routingKeys": ["<example-agency-verkey>"],
                            "serviceEndpoint": endpoint,
                        }],
                    }
                }
            })

        @staticmethod
        def validate_pre_sig(response: Message):
            response.check_for_attrs(
                [
                    ('@type', DIDExchange.RESPONSE),
                    '~thread',
                    'connection~sig'
                ]
            )

        @staticmethod
        def validate(response: Message, req_id: str):
            response.check_for_attrs(
                [
                    ('@type', DIDExchange.RESPONSE),
                    '~thread',
                    'connection'
                ]
            )

            Message.check_for_attrs_in_message(
                [
                    (Message.THREAD_ID, req_id)
                ],
                response['~thread']
            )

            Message.check_for_attrs_in_message(
                [
                    DIDDoc.DID,
                    DIDDoc.DID_DOC
                ],
                response[DIDExchange.CONNECTION]
            )

            DIDDoc.validate(response[DIDExchange.CONNECTION][DIDDoc.DID_DOC])

    class InviterStateMachine(BaseStateMachine, metaclass=InvokableStateMachineMeta):

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.__channel = None
            self.status = DIDExchangeStatus.Null

        async def handle(self, content_type, data):
            # every machine send response to channel with name = self id
            self.__channel = await WriteOnlyChannel.create(name=self.get_id())
            try:
                pass
            finally:
                await self.__channel.close()

    class InviteeStateMachine(BaseStateMachine, metaclass=InvokableStateMachineMeta):

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.__channel = None
            self.status = DIDExchangeStatus.Null

        async def handle(self, content_type, data):
            # every machine send response to channel with name = self id
            self.__channel = await WriteOnlyChannel.create(name=self.get_id())
            try:
                if content_type == DIDExchange.MESSAGE_CONTENT_TYPE:
                    kwargs = json.loads(data)
                    msg = Message(**kwargs)
                    if msg.type == DIDExchange.INVITE:
                        await self.__receive_invitation(msg)
                    elif msg.type == DIDExchange.RESPONSE:
                        pass
                else:
                    raise RuntimeError('Unknown content_type "%s"' % content_type)
            finally:
                await self.__channel.close()

        async def __receive_invitation(self, invitation: Message):
            if self.status == DIDExchangeStatus.Null:
                self.status = DIDExchangeStatus.Invited
                """TODO: remove
                await self.get_wallet().add_wallet_record(
                    'invitations',
                    invitation['recipientKeys'][0],
                    invitation.as_json()
                )
                """
                await self.__send(invitation)
            elif self.status == DIDExchangeStatus.Invited:
                # No change (Resend or new invite that supersedes)
                pass
            elif self.status == DIDExchangeStatus.Requested:
                # NewRelationship
                pass
            else:
                raise ImpossibleStatus()

        async def __send(self, invitation: Message):
            """Connection Request"""
            if self.status == DIDExchangeStatus.Null:
                raise ImpossibleStatus()
            elif self.status == DIDExchangeStatus.Invited:
                their = dict(
                    label=invitation['label'],
                    connection_key=invitation['recipientKeys'][0],
                )
                # Create my information for connection
                my_did, my_vk = await self.get_wallet().create_and_store_my_did()
                await self.get_wallet().set_did_metadata(my_did, their)
                # Send Connection Request to inviter
                request = Message({
                    '@type': DIDExchange.REQUEST,
                    'label': None,
                    'connection': {
                        'did': my_did,
                        'did_doc': {
                            "@context": "https://w3id.org/did/v1",
                            "id": my_did,
                            "publicKey": [{
                                "id": my_did + "#keys-1",
                                "type": "Ed25519VerificationKey2018",
                                "controller": my_did,
                                "publicKeyBase58": my_vk
                            }],
                            "service": [{
                                "id": my_did + ";indy",
                                "type": "IndyAgent",
                                "recipientKeys": [my_vk],
                                # "routingKeys": ["<example-agency-verkey>"],
                                "serviceEndpoint": None,
                            }],
                        }
                    }
                })
                await self.__channel.write(request.as_json())
                self.status = DIDExchangeStatus.Requested
            elif self.status == DIDExchangeStatus.Requested:
                # No change (Resend or req that supersedes)
                pass
            elif self.status == DIDExchangeStatus.Responded:
                # Resend (may indicate that out conn resp wasn't received)?
                pass
            else:
                raise ErrorStatus()
