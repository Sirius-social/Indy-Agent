import re
import base64
import uuid
from typing import Optional

from core.messages.message import Message
from core.messages.did_doc import DIDDoc
from core.serializer.json_serializer import JSONSerializer as Serializer
from core.base import MessageFeature, FeatureMeta
from core.wallet import WalletAgent
from .errors import BadInviteException


class Connection(MessageFeature, metaclass=FeatureMeta):

    """https://github.com/hyperledger/indy-agent/tree/master/python
      compatibility
    """

    FAMILY_NAME = "connections"
    VERSION = "1.0"
    FAMILY = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/" + FAMILY_NAME + "/" + VERSION + "/"

    CONNECTION = 'connection'
    INVITE = FAMILY + "invitation"
    REQUEST = FAMILY + "request"
    RESPONSE = FAMILY + "response"
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
    async def receive_invite_message(cls, msg: Message, agent_name: str, pass_phrase: str, my_label: str, my_endpoint: str) -> None:
        pass

    @classmethod
    async def receive_invite_link(cls, link: str, agent_name: str, pass_phrase: str, my_label: str, my_endpoint: str):
        await WalletAgent.ensure_agent_is_open(agent_name, pass_phrase)
        matches = re.match("(.+)?c_i=(.+)", link)
        if not matches:
            raise BadInviteException("Invite string is improperly formatted")
        invite_msg = Serializer.deserialize(
            base64.urlsafe_b64decode(matches.group(2)).decode('utf-8')
        )
        if cls.endorsement(invite_msg):
            cls.receive_invite_message(invite_msg, agent_name, pass_phrase, my_label, my_endpoint)
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
                    ('@type', Connection.INVITE),
                    'label',
                    'recipientKeys',
                    'serviceEndpoint'
                ]
            )

            return invite_msg

        @staticmethod
        def build(label: str, connection_key: str, endpoint: str) -> str:
            msg = Message({
                '@type': Connection.INVITE,
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
                request[Connection.CONNECTION][DIDDoc.DID_DOC]['publicKey'][0]['controller'],
                request[Connection.CONNECTION][DIDDoc.DID_DOC]['publicKey'][0]['publicKeyBase58'],
                request[Connection.CONNECTION][DIDDoc.DID_DOC]['service'][0]['serviceEndpoint']
            )

        @staticmethod
        def build(label: str, my_did: str, my_vk: str, endpoint: str) -> Message:
            return Message({
                '@type': Connection.REQUEST,
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
                    ('@type', Connection.REQUEST),
                    '@id',
                    'label',
                    Connection.CONNECTION
                ]
            )

            Message.check_for_attrs_in_message(
                [
                    DIDDoc.DID,
                    DIDDoc.DID_DOC
                ],
                request[Connection.CONNECTION]
            )

            DIDDoc.validate(request[Connection.CONNECTION][DIDDoc.DID_DOC])

    class Response:
        @staticmethod
        def build(req_id: str, my_did: str, my_vk: str, endpoint: str) -> Message:
            return Message({
                '@type': Connection.RESPONSE,
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
                    ('@type', Connection.RESPONSE),
                    '~thread',
                    'connection~sig'
                ]
            )

        @staticmethod
        def validate(response: Message, req_id: str):
            response.check_for_attrs(
                [
                    ('@type', Connection.RESPONSE),
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
                response[Connection.CONNECTION]
            )

            DIDDoc.validate(response[Connection.CONNECTION][DIDDoc.DID_DOC])
