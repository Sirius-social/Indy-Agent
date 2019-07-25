import re
import uuid
import base64
from typing import Optional

from core.base import MessageFeature, FeatureMeta
from core.messages.did_doc import DIDDoc
from core.messages.message import Message
from core.serializer.json_serializer import JSONSerializer as Serializer
from core.wallet import WalletAgent
from state_machines.base import BaseStateMachine
from .errors import BadInviteException


class StateMachine(BaseStateMachine):

    STATUS_NULL = 0

    async def handle(self, content_type, data):
        pass


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

    # TODO: Following 2 methods should be available on base Message.
    #  Or the context should have verkey and endpoint info so that an error message can be returned.
    @staticmethod
    def extract_verkey_endpoint(msg: Message) -> (Optional, Optional):
        """
        Extract verkey and endpoint that will be used to send message back to the sender of this message. Might return None.
        """
        vks = msg.get(DIDExchange.CONNECTION, {}).get(DIDDoc.DID_DOC, {}).get('publicKey')
        vk = vks[0].get('publicKeyBase58') if vks and isinstance(vks, list) and len(vks) > 0 else None
        endpoints = msg.get(DIDExchange.CONNECTION, {}).get(DIDDoc.DID_DOC, {}).get('service')
        endpoint = endpoints[0].get('serviceEndpoint') if endpoints and isinstance(endpoints, list) and len(
            endpoints) > 0 else None
        return vk, endpoint

    @staticmethod
    def extract_their_info(msg: Message):
        """
        Extract the other participant's DID, verkey and endpoint
        :param msg:
        :return: Return a 3-tuple of (DID, verkey, endpoint
        """
        their_did = msg[DIDExchange.CONNECTION][DIDDoc.DID]
        # NOTE: these values are pulled based on the minimal connectathon format. Full processing
        #  will require full DIDDoc storage and evaluation.
        their_vk = msg[DIDExchange.CONNECTION][DIDDoc.DID_DOC]['publicKey'][0]['publicKeyBase58']
        their_endpoint = msg[DIDExchange.CONNECTION][DIDDoc.DID_DOC]['service'][0]['serviceEndpoint']
        return their_did, their_vk, their_endpoint
