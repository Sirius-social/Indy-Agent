import re
import json
import uuid
import time
import struct
import logging
import base64
import hashlib

from channels.db import database_sync_to_async

import indy.crypto
import core.indy_sdk_utils as indy_sdk_utils
import core.const
from core.wallet import WalletOperationError
from core.base import WireMessageFeature, FeatureMeta, WriteOnlyChannel, EndpointTransport
from core.messages.did_doc import DIDDoc
from core.messages.message import Message
from core.messages.errors import ValidationException as MessageValidationException
from core.serializer.json_serializer import JSONSerializer as Serializer
from core.wallet import WalletAgent, InvokableStateMachineMeta, WalletConnection
from state_machines.base import BaseStateMachine, MachineIsDone
from core.aries_rfcs.features.feature_0095_basic_message.feature import BasicMessage
from core.aries_rfcs.features.feature_0048_trust_ping.feature import TrustPing
from core.aries_rfcs.features.feature_0015_acks.feature import AckMessage
from core.aries_rfcs.concepts.concept_0094_cross_domain.concept import RoutingMessage
from transport.const import WIRED_CONTENT_TYPES
from transport.models import Invitation
from .errors import *
from .statuses import *


def __load_invitation(wallet_uid: str, connection_key: str):
    inst = Invitation.objects.filter(endpoint__wallet__uid=wallet_uid, connection_key=connection_key).first()
    return inst


async def load_invitation(wallet_uid: str, connection_key: str):
    return await database_sync_to_async(__load_invitation)(wallet_uid, connection_key)


class ConnectionProtocol(WireMessageFeature, metaclass=FeatureMeta):
    """https://github.com/hyperledger/aries-rfcs/tree/master/features/0160-connection-protocol"""

    FAMILY_NAME = "connections"
    VERSION = "1.0"
    FAMILY = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/" + FAMILY_NAME + "/" + VERSION

    CONNECTION = 'connection'
    INVITE = FAMILY + "/invitation"
    REQUEST = FAMILY + "/request"
    RESPONSE = FAMILY + "/response"
    PROBLEM_REPORT = FAMILY + '/problem_report'
    # Problem codes
    REQUEST_NOT_ACCEPTED = "request_not_accepted"
    REQUEST_PROCESSING_ERROR = 'request_processing_error'
    RESPONSE_NOT_ACCEPTED = "response_not_accepted"
    RESPONSE_PROCESSING_ERROR = 'response_processing_error'
    RESPONSE_FOR_UNKNOWN_REQUEST = "response_for_unknown_request"
    # internal usage definitions
    MESSAGE_CONTENT_TYPE = 'application/json'
    WIRED_CONTENT_TYPE = WIRED_CONTENT_TYPES[0]

    @classmethod
    def endorsement(cls, msg: Message) -> bool:
        if msg.type in [AckMessage.ACK, TrustPing.PING, TrustPing.PING_RESPONSE, ConnectionProtocol.PROBLEM_REPORT]:
            return True
        matches = re.match("(.+/.+/\d+.\d+).+", msg.type)
        if matches:
            family = matches.group(1)
            return family in cls.FAMILY
        return False

    @classmethod
    async def handle(cls, agent_name: str, wire_message: bytes, my_label: str=None, my_endpoint: str=None) -> bool:
        unpacked = await WalletAgent.unpack_message(agent_name, wire_message)
        kwargs = json.loads(unpacked['message'])
        message = Message(**kwargs)
        if message.get('@type', None) is None:
            return False
        if message.type == cls.REQUEST:
            state_machine_id = unpacked['sender_verkey']
            machine_class = ConnectionProtocol.ConnProtocolInviterStateMachine
            invitation = await load_invitation(agent_name, unpacked['recipient_verkey'])
            await WalletAgent.start_state_machine(
                agent_name=agent_name, machine_class=machine_class, machine_id=state_machine_id, endpoint=my_endpoint,
                label=my_label, status=DIDExchangeStatus.Invited,
                my_did=invitation.my_did if invitation else None
            )
            await WalletAgent.invoke_state_machine(
                agent_name=agent_name, id_=state_machine_id,
                content_type=cls.WIRED_CONTENT_TYPE, data=wire_message
            )
            return True
        elif message.type == ConnectionProtocol.RESPONSE:
            state_machine_id = message['connection~sig']['signer']
            await WalletAgent.invoke_state_machine(
                agent_name=agent_name, id_=state_machine_id,
                content_type=cls.WIRED_CONTENT_TYPE, data=wire_message
            )
            return True
        elif message.type in [TrustPing.PING, TrustPing.PING_RESPONSE]:
            state_machine_id = unpacked['sender_verkey']
            await WalletAgent.invoke_state_machine(
                agent_name=agent_name, id_=state_machine_id,
                content_type=cls.WIRED_CONTENT_TYPE, data=wire_message
            )
            return True
        elif message.type == ConnectionProtocol.PROBLEM_REPORT:
            state_machine_id = message.to_dict().get('connection~sig', {}).get('signer')
            if state_machine_id:
                await WalletAgent.invoke_state_machine(
                    agent_name=agent_name, id_=state_machine_id,
                    content_type=cls.WIRED_CONTENT_TYPE, data=wire_message
                )
                return True
            else:
                logging.error('Problem report', message.as_json())
                return True
        else:
            return False

    @classmethod
    async def generate_invite_message(cls, label: str, endpoint: str, agent_name: str, pass_phrase: str,
                                      extra: dict=None, seed: str=None, connection_key: str=None) -> Message:
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
        if seed and connection_key:
            raise RuntimeError('seed and connection_key can not be set both')
        if seed:
            safety_seed = hashlib.md5(seed.encode()).hexdigest()
            connection_key = await WalletAgent.create_key(agent_name, pass_phrase, seed=safety_seed)
        elif not connection_key:
            connection_key = await WalletAgent.create_key(agent_name, pass_phrase)
        data = {
            '@id': hashlib.md5(connection_key.encode()).hexdigest(),
            '@type': cls.INVITE,
            'label': label,
            'recipientKeys': [connection_key],
            'serviceEndpoint': endpoint,
            # routingKeys not specified, but here is where they would be put in the invite.
        }
        if extra:
            data.update(extra)
        invite_msg = Message(data)
        return invite_msg

    @classmethod
    async def generate_invite_link(cls, label: str, endpoint: str, agent_name: str, pass_phrase: str,
                                   extra: dict=None, seed: str=None, connection_key: str=None):
        invite_msg = await cls.generate_invite_message(
            label, endpoint, agent_name, pass_phrase, extra, seed, connection_key
        )
        b64_invite = base64.urlsafe_b64encode(Serializer.serialize(invite_msg)).decode('ascii')
        return '?c_i=' + b64_invite, invite_msg

    @classmethod
    async def receive_invite_message(
            cls, msg: Message, agent_name: str, pass_phrase: str, my_label: str, my_endpoint: str, ttl: int, my_did: str=None
    ) -> str:
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
        if not cls.endorsement(msg):
            return None
        connection_key = msg['recipientKeys'][0]
        state_machine_id = connection_key
        log_channel_name = 'invite-log/' + uuid.uuid4().hex
        await WalletAgent.start_state_machine(
            agent_name=agent_name,
            machine_class=ConnectionProtocol.ConnProtocolInviteeStateMachine,
            machine_id=state_machine_id,
            ttl=ttl,
            endpoint=my_endpoint,
            label=my_label,
            status=DIDExchangeStatus.Null,
            log_channel_name=log_channel_name,
            my_did=my_did
        )
        await WalletAgent.invoke_state_machine(
            agent_name=agent_name,
            id_=state_machine_id,
            content_type=cls.MESSAGE_CONTENT_TYPE,
            data=msg.as_json()
        )
        return log_channel_name

    @classmethod
    async def receive_invite_link(
            cls, link: str, agent_name: str, pass_phrase: str, my_label: str, my_endpoint: str, ttl: int, my_did: str=None
    ):
        await WalletAgent.ensure_agent_is_open(agent_name, pass_phrase)
        matches = re.match("(.+)?c_i=(.+)", link)
        if not matches:
            raise BadInviteException("Invite string is improperly formatted")
        invite_msg = Serializer.deserialize(
            base64.urlsafe_b64decode(matches.group(2)).decode('utf-8')
        )
        if cls.endorsement(invite_msg):
            return await cls.receive_invite_message(invite_msg, agent_name, pass_phrase, my_label, my_endpoint, ttl, my_did)
        else:
            return None

    @classmethod
    def build_problem_report_for_connections(cls, problem_code, problem_str, thread_id: str=None) -> Message:
        initialized = {
            "@type": "{}/problem_report".format(cls.FAMILY),
            "problem-code": problem_code,
            "explain": problem_str
        }
        if thread_id:
            initialized['~thread'] = {Message.THREAD_ID: thread_id, Message.SENDER_ORDER: 0}
        return Message(initialized)

    @classmethod
    async def validate_common_message_blocks(cls, msg: Message, is_inviter: bool):
        try:
            msg.validate_common_blocks()
            return True, None
        except MessageValidationException as e:
            logging.exception('Validation error while parsing message: %s' % msg.as_json())
            their_did = msg.context.get('from_did')
            if their_did:
                if is_inviter:
                    problem_code = ConnectionProtocol.REQUEST_NOT_ACCEPTED
                else:
                    problem_code = ConnectionProtocol.RESPONSE_NOT_ACCEPTED
                err_msg = cls.build_problem_report_for_connections(
                    problem_code,
                    str(e.exception),
                    thread_id=msg.id
                )
                return False, err_msg
            else:
                return False, None
        except Exception as e:
            logging.exception('Validation error while parsing message: %s' % str(e))
            return False, None

    @classmethod
    async def send_message_to_agent(cls, to_did: str, msg: Message, wallet: WalletConnection):
        their_did = to_did
        pairwise_info = await wallet.get_pairwise(their_did)
        pairwise_meta = pairwise_info['metadata']
        my_did = pairwise_info['my_did']
        their_endpoint = pairwise_meta['their_endpoint']
        their_vk = pairwise_meta['their_vk']
        their_routing_keys = pairwise_meta.get('their_routing_keys', None)
        my_vk = await wallet.key_for_local_did(my_did)
        await cls.send_message_to_endpoint_and_key(their_vk, their_endpoint, msg, wallet, my_vk, their_routing_keys)

    @staticmethod
    async def send_message_to_endpoint_and_key(
            their_ver_key, their_endpoint: str, msg: Message,
            wallet: WalletConnection, my_ver_key: str=None, their_routing_keys: list=None
    ):
        # If my_ver_key is omitted, anon-crypt is used inside pack.
        try:
            if their_routing_keys:
                wire_message = await RoutingMessage.pack(
                    msg,
                    wallet,
                    their_ver_key,
                    their_routing_keys,
                    my_ver_key
                )
            else:
                wire_message = await wallet.pack_message(
                    Serializer.serialize(msg).decode('utf-8'),
                    their_ver_key,
                    my_ver_key
                )
        except Exception as e:
            logging.exception(str(e))
            raise
        else:
            transport = EndpointTransport(address=their_endpoint)
            await transport.send_wire_message(wire_message)

    @staticmethod
    async def unpack_agent_message(wire_msg_bytes, wallet: WalletConnection):
        if isinstance(wire_msg_bytes, str):
            wire_msg_bytes = bytes(wire_msg_bytes, 'utf-8')
        unpacked = await wallet.unpack_message(wire_msg_bytes)
        from_key = None
        from_did = None
        if 'sender_verkey' in unpacked:
            from_key = unpacked['sender_verkey']
            from_did = await indy_sdk_utils.did_for_key(wallet, unpacked['sender_verkey'])
        to_key = unpacked['recipient_verkey']
        to_did = await indy_sdk_utils.did_for_key(wallet, unpacked['recipient_verkey'])

        unpacked_message = json.loads(unpacked['message'])
        is_vcx = False
        if ConnectionProtocol.CONNECTION in unpacked_message:
            for from_attr, to_attr in [(DIDDoc.VCX_DID, DIDDoc.DID), (DIDDoc.VCX_DID_DOC, DIDDoc.DID_DOC)]:
                if from_attr in unpacked_message[ConnectionProtocol.CONNECTION]:
                    unpacked_message[ConnectionProtocol.CONNECTION][to_attr] = unpacked_message[ConnectionProtocol.CONNECTION][from_attr]
                    is_vcx = True
        repacked_message = json.dumps(unpacked_message)
        msg = Serializer.deserialize(repacked_message)
        msg.context = {
            'from_did': from_did,  # Could be None
            'to_did': to_did,  # Could be None
            'from_key': from_key,  # Could be None
            'to_key': to_key,
            'is_vcx': is_vcx
        }
        return msg

    @staticmethod
    async def sign_agent_message_field(wallet: WalletConnection, field_value, my_vk):
        timestamp_bytes = struct.pack(">Q", int(time.time()))

        sig_data_bytes = timestamp_bytes + json.dumps(field_value).encode('ascii')
        sig_data = base64.urlsafe_b64encode(sig_data_bytes).decode('ascii')

        signature_bytes = await wallet.crypto_sign(my_vk, sig_data_bytes)
        signature = base64.urlsafe_b64encode(
            signature_bytes
        ).decode('ascii')

        return {
            "@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/signature/1.0/ed25519Sha512_single",
            "signer": my_vk,
            "sig_data": sig_data,
            "signature": signature
        }

    @staticmethod
    async def unpack_and_verify_signed_agent_message_field(signed_field):
        signature_bytes = base64.urlsafe_b64decode(signed_field['signature'].encode('ascii'))
        sig_data_bytes = base64.urlsafe_b64decode(signed_field['sig_data'].encode('ascii'))
        sig_verified = await indy.crypto.crypto_verify(
            signed_field['signer'],
            sig_data_bytes,
            signature_bytes
        )
        data_bytes = base64.urlsafe_b64decode(signed_field['sig_data'])
        timestamp = struct.unpack(">Q", data_bytes[:8])
        field_json = data_bytes[8:]
        if isinstance(field_json, bytes):
            field_json = field_json.decode('utf-8')
        return json.loads(field_json), sig_verified

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
                    ('@type', ConnectionProtocol.INVITE),
                    'label',
                    'recipientKeys',
                    'serviceEndpoint'
                ]
            )

            return invite_msg

        @staticmethod
        def build(label: str, connection_key: str, endpoint: str) -> str:
            msg = Message({
                '@type': ConnectionProtocol.INVITE,
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
                request[ConnectionProtocol.CONNECTION][DIDDoc.DID_DOC]['publicKey'][0]['controller'],
                request[ConnectionProtocol.CONNECTION][DIDDoc.DID_DOC]['publicKey'][0]['publicKeyBase58'],
                request[ConnectionProtocol.CONNECTION][DIDDoc.DID_DOC]['service'][0]['serviceEndpoint']
            )

        @staticmethod
        def build(label: str, my_did: str, my_vk: str, endpoint: str, is_vcx: bool=False) -> Message:
            if is_vcx:
                recipient_key = my_did + '#1'
                return Message({
                    '@type': ConnectionProtocol.REQUEST,
                    '@id': str(uuid.uuid4()),
                    'label': label,
                    'connection': {
                        'DID': my_did,
                        'DIDDoc': {
                            "@context": "https://w3id.org/did/v1",
                            "id": my_did,
                            "authentication": [
                                {
                                    "publicKey": recipient_key,
                                    "type": "Ed25519SignatureAuthentication2018"
                                }
                            ],
                            "publicKey": [{
                                "id": "1",
                                "type": "Ed25519VerificationKey2018",
                                "controller": my_did,
                                "publicKeyBase58": my_vk
                            }],
                            "service": [{
                                "id": 'did:peer:' + my_did + ";indy",
                                "type": "IndyAgent",
                                "priority": 0,
                                "recipientKeys": [recipient_key],
                                "serviceEndpoint": endpoint,
                            }],
                        }
                    }
                })
            else:
                return Message({
                    '@type': ConnectionProtocol.REQUEST,
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
                    ('@type', ConnectionProtocol.REQUEST),
                    '@id',
                    'label',
                    ConnectionProtocol.CONNECTION
                ]
            )

            Message.check_for_attrs_in_message(
                [
                    DIDDoc.DID,
                    DIDDoc.DID_DOC
                ],
                request[ConnectionProtocol.CONNECTION]
            )

            DIDDoc.validate(request[ConnectionProtocol.CONNECTION][DIDDoc.DID_DOC])

    class Response:

        @staticmethod
        def build(req_id: str, my_did: str, my_vk: str, endpoint: str, is_vcx: bool) -> Message:
            if is_vcx:
                recipient_key = my_did + '#1'
                return Message({
                    '@type': ConnectionProtocol.RESPONSE,
                    '@id': str(uuid.uuid4()),
                    '~thread': {Message.THREAD_ID: req_id, Message.SENDER_ORDER: 0, Message.RECEIVED_ORDERS: {}},
                    "~please_ack": {},
                    'connection': {
                        'DID': my_did,
                        'DIDDoc': {
                            "@context": "https://w3id.org/did/v1",
                            "id": my_did,
                            "authentication": [
                                {
                                    "publicKey": recipient_key,
                                    "type": "Ed25519SignatureAuthentication2018"
                                }
                            ],
                            "publicKey": [{
                                "id": "1",
                                "type": "Ed25519VerificationKey2018",
                                "controller": my_did,
                                "publicKeyBase58": my_vk
                            }],
                            "service": [{
                                "id": 'did:peer:' + my_did + ";indy",
                                "type": "IndyAgent",
                                "priority": 0,
                                "recipientKeys": [recipient_key],
                                "serviceEndpoint": endpoint,
                            }],
                        }
                    }
                })
            else:
                return Message({
                    '@type': ConnectionProtocol.RESPONSE,
                    '@id': str(uuid.uuid4()),
                    '~thread': {Message.THREAD_ID: req_id, Message.SENDER_ORDER: 0, Message.RECEIVED_ORDERS: {}},
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
                    ('@type', ConnectionProtocol.RESPONSE),
                    '~thread',
                    'connection~sig'
                ]
            )

        @staticmethod
        def validate(response: Message, req_id: str):
            response.check_for_attrs(
                [
                    ('@type', ConnectionProtocol.RESPONSE),
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
                response[ConnectionProtocol.CONNECTION]
            )

            DIDDoc.validate(response[ConnectionProtocol.CONNECTION][DIDDoc.DID_DOC])

    class ConnProtocolInviterStateMachine(BaseStateMachine, metaclass=InvokableStateMachineMeta):

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.status = DIDExchangeStatus.Invited
            self.label = None
            self.endpoint = None
            self.ack_message_id = None
            self.my_did = None

        async def handle(self, content_type, data):
            try:
                if content_type == ConnectionProtocol.MESSAGE_CONTENT_TYPE:
                    kwargs = json.loads(data)
                    msg = Message(**kwargs)
                elif content_type in WIRED_CONTENT_TYPES:
                    msg = await ConnectionProtocol.unpack_agent_message(data, self.get_wallet())
                else:
                    raise RuntimeError('Unknown content_type "%s"' % content_type)
                await self.__log('Receive', msg.to_dict())
                if msg.type == ConnectionProtocol.REQUEST:
                    await self.__receive_connection_request(msg)
                elif msg.type in [TrustPing.PING, AckMessage.ACK]:
                    await self.__receive_connection_ack(msg)
                elif msg.type == ConnectionProtocol.PROBLEM_REPORT:
                    if self.status == DIDExchangeStatus.Responded:
                        # Stay in same state - retryable
                        pass
                    else:
                        raise ImpossibleStatus()
                else:
                    logging.error('Unexpected message type: %s' % msg.type)
            except Exception as e:
                if not isinstance(e, MachineIsDone):
                    logging.exception('Base machine terminated with exception')
                await self.done()

        async def done(self):
            await self.__log('Done')
            await super().done()

        async def __log(self, event: str, details: dict=None):
            event_message = '%s (%s)' % (event, self.get_id())
            await self.get_wallet().log(message=event_message, details=details)

        async def __log_pairwise_creation(self, details: dict):
            await self.get_wallet().log(message=core.const.NEW_PAIRWISE, details=details)

        async def __log_pairwise_update(self, details: dict):
            await self.get_wallet().log(message=core.const.UPDATE_PAIRWISE, details=details)

        async def __receive_connection_request(self, msg: Message):
            if self.status == DIDExchangeStatus.Invited:
                success, err_msg = await ConnectionProtocol.validate_common_message_blocks(msg, True)
                if success:
                    try:
                        ConnectionProtocol.Request.validate(msg)
                    except Exception as e:
                        logging.exception('Error while parsing message %s with error %s' % (msg.as_json(), str(e)))
                        their_did, their_vk, their_endpoint, their_routing_keys = BasicMessage.extract_their_info(
                            msg, ConnectionProtocol.CONNECTION
                        )
                        if None in (their_vk, their_endpoint):
                            # Cannot extract verkey and endpoint hence won't send any message back.
                            logging.error('Encountered error parsing connection request %s' % str(e))
                        else:
                            # Sending an error message back to the sender
                            err_msg = ConnectionProtocol.build_problem_report_for_connections(
                                ConnectionProtocol.REQUEST_NOT_ACCEPTED,
                                str(e),
                                thread_id=msg.id
                            )
                            await ConnectionProtocol.send_message_to_endpoint_and_key(
                                their_ver_key=their_vk,
                                their_endpoint=their_endpoint,
                                msg=err_msg,
                                wallet=self.get_wallet(),
                                their_routing_keys=their_routing_keys
                            )
                            await self.__log('Send report problem', err_msg.to_dict())
                    else:
                        try:
                            connection_key = msg.context['to_key']
                            await self.__log('Received connection request for key "%s"' % connection_key)
                            label = msg['label']
                            their_did, their_vk, their_endpoint, their_routing_keys = BasicMessage.extract_their_info(
                                msg, ConnectionProtocol.CONNECTION
                            )
                            # Store their information from request
                            await indy_sdk_utils.store_their_did(self.get_wallet(), their_did, their_vk)
                            await self.get_wallet().set_did_metadata(
                                their_did,
                                metadata=dict(label=label, endpoint=their_endpoint)
                            )
                            if self.my_did:
                                await self.__log('Static DID: "%s"' % self.my_did)
                                my_did, my_vk = self.my_did, await self.get_wallet().key_for_local_did(self.my_did)
                            else:
                                my_did, my_vk = await indy_sdk_utils.create_and_store_my_did(self.get_wallet())

                            pairwise_kwargs = dict(
                                their_did=their_did,
                                my_did=my_did,
                                metadata={
                                    'label': label,
                                    'req_id': msg['@id'],
                                    'their_endpoint': their_endpoint,
                                    'their_vk': their_vk,
                                    'my_vk': my_vk,
                                    'their_routing_keys': their_routing_keys,
                                    'connection_key': connection_key  # used to sign the response
                                }
                            )
                            pairwise = await self.get_wallet().get_pairwise(their_did)
                            if pairwise:
                                await self.get_wallet().set_pairwise_metadata(their_did, pairwise_kwargs['metadata'])
                                await self.__log_pairwise_update(pairwise_kwargs)
                            else:
                                await self.get_wallet().create_pairwise(**pairwise_kwargs)
                                await self.__log_pairwise_creation(pairwise_kwargs)
                        except Exception as e:
                            logging.exception('Error while process invitee request')
                            raise
                        else:
                            is_vcx = msg.context.get('is_vcx', False)
                            response_msg = await self.__send_connection_response(their_did, is_vcx)
                            await self.__log('Send', response_msg.to_dict())
                            self.ack_message_id = response_msg.id
                            self.status = DIDExchangeStatus.Responded
                elif err_msg:
                    their_did = msg.context.get('from_did')
                    if their_did:
                        await ConnectionProtocol.send_message_to_agent(their_did, err_msg, self.get_wallet())
                        await self.__log('Send report problem', err_msg.to_dict())
                    logging.error('Validation error while parsing message: %s', msg.as_json())
                else:
                    logging.error('Validation error while parsing message: %s', msg.as_json())
            else:
                raise ErrorStatus()

        async def __receive_connection_ack(self, msg: Message):
            if self.status == DIDExchangeStatus.Responded:
                try:
                    if msg.type == TrustPing.PING:
                        TrustPing.Ping.validate(msg)
                        if msg.get('response_requested'):
                            pong = TrustPing.Pong.build(msg.id)
                            to_did = msg.context['to_did']
                            await ConnectionProtocol.send_message_to_agent(to_did, pong, self.get_wallet())
                    elif msg.type == AckMessage.ACK:
                        AckMessage.validate(msg)
                    else:
                        raise RuntimeError('Unexpected message type "%s"' % msg.type)
                except:
                    err_msg = ConnectionProtocol.build_problem_report_for_connections(
                        ConnectionProtocol.RESPONSE_FOR_UNKNOWN_REQUEST,
                        'Uncknown ack thread id',
                        thread_id=msg.id
                    )
                    to_did = msg.context['to_did']
                    await ConnectionProtocol.send_message_to_agent(to_did, err_msg, self.get_wallet())
                else:
                    await self.done()
            else:
                raise ImpossibleStatus()

        async def __send_connection_response(self, their_did: str, is_vcx: bool=False):
            pairwise_info = await self.get_wallet().get_pairwise(their_did)
            pairwise_meta = pairwise_info['metadata']
            my_did = pairwise_info['my_did']
            my_vk = await self.get_wallet().key_for_local_did(my_did)
            response_msg = ConnectionProtocol.Response.build(
                pairwise_meta['req_id'], my_did, my_vk, self.endpoint, is_vcx
            )
            # Apply signature to connection field, sign it with the key used in the invitation and request
            response_msg['connection~sig'] = \
                await ConnectionProtocol.sign_agent_message_field(
                    self.get_wallet(),
                    response_msg['connection'],
                    pairwise_meta["connection_key"]
                )
            del response_msg['connection']
            await ConnectionProtocol.send_message_to_agent(their_did, response_msg, self.get_wallet())
            return response_msg
        pass

    class ConnProtocolInviteeStateMachine(BaseStateMachine, metaclass=InvokableStateMachineMeta):

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.status = DIDExchangeStatus.Null
            self.label = None
            self.endpoint = None
            self.log_channel_name = None
            self.my_did = None
            self.__log_channel = None

        async def handle(self, content_type, data):
            try:
                if content_type == ConnectionProtocol.MESSAGE_CONTENT_TYPE:
                    kwargs = json.loads(data)
                    msg = Message(**kwargs)
                elif content_type in WIRED_CONTENT_TYPES:
                    msg = await ConnectionProtocol.unpack_agent_message(data, self.get_wallet())
                else:
                    raise RuntimeError('Unknown content_type "%s"' % content_type)
                await self.__log('Receive', msg.to_dict())
                if msg.type == ConnectionProtocol.INVITE:
                    await self.__receive_invitation(msg)
                elif msg.type == ConnectionProtocol.RESPONSE:
                    await self.__receive_connection_response(msg)
                elif msg.type == ConnectionProtocol.PROBLEM_REPORT:
                    if self.status == DIDExchangeStatus.Requested:
                        # Stay in same state - retryable
                        pass
                    else:
                        raise ImpossibleStatus()
                else:
                    logging.error('Unexpected message type: %s' % msg.type)
            except Exception as e:
                if not isinstance(e, MachineIsDone):
                    logging.exception('Base machine terminated with exception')
                await self.done()

        async def done(self):
            if self.__log_channel is not None:
                await self.__log('Done')
                await self.__log_channel.close()
            await super().done()

        async def __log(self, event: str, details: dict=None):
            event_message = '%s (%s)' % (event, self.get_id())
            await self.get_wallet().log(message=event_message, details=details)
            if self.__log_channel is None:
                self.__log_channel = await WriteOnlyChannel.create(self.log_channel_name)
            if not self.__log_channel.is_closed:
                await self.__log_channel.write([event_message, details])

        async def __log_pairwise_creation(self, details: dict):
            await self.get_wallet().log(message=core.const.NEW_PAIRWISE, details=details)
            if self.__log_channel and not self.__log_channel.is_closed:
                await self.__log_channel.write([core.const.NEW_PAIRWISE, details])

        async def __log_pairwise_update(self, details: dict):
            await self.get_wallet().log(message=core.const.UPDATE_PAIRWISE, details=details)
            if self.__log_channel and not self.__log_channel.is_closed:
                await self.__log_channel.write([core.const.UPDATE_PAIRWISE, details])

        async def __receive_invitation(self, invitation: Message):
            if self.status == DIDExchangeStatus.Requested:
                # NewRelationship
                self.status = DIDExchangeStatus.Null
            if self.status == DIDExchangeStatus.Null:
                self.status = DIDExchangeStatus.Invited
                await self.__send_connection_request(invitation)
                self.status = DIDExchangeStatus.Requested
            elif self.status == DIDExchangeStatus.Invited:
                # No change (Resend or new invite that supersedes)
                pass
            else:
                raise ImpossibleStatus()

        async def __send_connection_request(self, invitation: Message):
            """Connection Request"""
            their_routing_keys = invitation.get('routingKeys', [])
            their_ver_key = invitation['recipientKeys'][0]
            their = dict(
                label=invitation['label'],
                connection_key=their_ver_key,
                endpoint=invitation['serviceEndpoint'],
                routing_keys=their_routing_keys,
                ver_keys=invitation['recipientKeys']
            )
            # Create my information for connection
            if self.my_did:
                my_did, my_vk = self.my_did, await self.get_wallet().key_for_local_did(self.my_did)
            else:
                my_did, my_vk = await indy_sdk_utils.create_and_store_my_did(self.get_wallet())
            await self.get_wallet().set_did_metadata(my_did, their)
            # Send Connection Request to inviter
            is_vcx = len(their_routing_keys) > 0
            request = ConnectionProtocol.Request.build(self.label, my_did, my_vk, self.endpoint, is_vcx)
            try:
                if their_routing_keys:
                    wire_message = await RoutingMessage.pack(
                        msg=request,
                        wallet=self.get_wallet(),
                        their_ver_key=their_ver_key,
                        routing_keys=their_routing_keys,
                        my_ver_key=my_vk
                    )
                else:
                    wire_message = await self.get_wallet().pack_message(
                        message=Serializer.serialize(request).decode('utf-8'),
                        their_ver_key=their_ver_key,
                        my_ver_key=my_vk
                    )
                transport = EndpointTransport(address=their['endpoint'])
                await transport.send_wire_message(wire_message)
                await self.__log('Send', request.to_dict())
            except Exception as e:
                logging.exception(str(e))
                raise

        async def __receive_connection_response(self, msg: Message):
            if self.status == DIDExchangeStatus.Requested:
                success, err_msg = await ConnectionProtocol.validate_common_message_blocks(msg, False)
                if success:
                    my_did = msg.context['to_did']
                    if my_did is None:
                        msg[ConnectionProtocol.CONNECTION], sig_verified = \
                            await self.agent.unpack_and_verify_signed_agent_message_field(msg['connection~sig'])
                        if not sig_verified:
                            logging.error(
                                'Encountered error parsing connection response. Connection request not found.'
                            )
                        else:
                            their_did, their_vk, their_endpoint, routing_keys = BasicMessage.extract_their_info(
                                msg, ConnectionProtocol.CONNECTION
                            )
                            if None in (their_vk, their_endpoint):
                                # Cannot extract verkey and endpoint hence won't send any message back.
                                logging.error(
                                    'Encountered error parsing connection response. Connection request not found.'
                                )
                            else:
                                # Sending an error message back to the sender
                                err_msg = ConnectionProtocol.build_problem_report_for_connections(
                                    ConnectionProtocol.RESPONSE_FOR_UNKNOWN_REQUEST,
                                    "No corresponding connection request found",
                                    thread_id=msg.id
                                )
                                await ConnectionProtocol.send_message_to_endpoint_and_key(
                                    their_ver_key=their_vk,
                                    their_endpoint=their_endpoint,
                                    msg=err_msg,
                                    their_routing_keys=routing_keys
                                )
                                await self.__log('Send report problem', err_msg.to_dict())
                    else:
                        # Following should return an error if key not found for given DID
                        my_vk = await self.get_wallet().key_for_local_did(my_did)
                        # process signed field
                        msg[ConnectionProtocol.CONNECTION], sig_verified = \
                            await ConnectionProtocol.unpack_and_verify_signed_agent_message_field(msg['connection~sig'])
                        their_did, their_vk, their_endpoint, their_routing_keys = BasicMessage.extract_their_info(
                            msg, ConnectionProtocol.CONNECTION
                        )
                        # Verify that their_vk (from did doc) matches msg_vk
                        msg_vk = msg.context['from_key']
                        if their_vk != msg_vk:
                            err_msg = \
                                ConnectionProtocol.build_problem_report_for_connections(
                                    ConnectionProtocol.RESPONSE_NOT_ACCEPTED,
                                    "Key provided in response does not match expected key",
                                    thread_id=msg.id
                                )
                            logging.error("Key provided in response does not match expected key")
                            await ConnectionProtocol.send_message_to_endpoint_and_key(
                                their_ver_key=their_vk, their_endpoint=their_endpoint, msg=err_msg,
                                wallet=self.get_wallet(), their_routing_keys=their_routing_keys
                            )
                            await self.__log('Send report problem', err_msg.to_dict())
                            return
                        my_did_meta = await self.get_wallet().get_did_metadata(my_did)
                        label = my_did_meta['label']
                        # Clear DID metadata. This info will be stored in pairwise meta.
                        await self.get_wallet().set_did_metadata(my_did, metadata=None)
                        # In the final implementation, a signature will be provided to verify changes to
                        # the keys and DIDs to be used long term in the relationship.
                        # Both the signature and signature check are omitted for now until specifics of the
                        # signature are decided.

                        # Store their information from response
                        await indy_sdk_utils.store_their_did(self.get_wallet(), their_did, their_vk)
                        await self.get_wallet().set_did_metadata(
                            their_did,
                            {
                                'label': label,
                                'endpoint': their_endpoint,
                                'routing_keys': their_routing_keys
                            }
                        )
                        # Create pairwise relationship between my did and their did
                        creation_kwargs = dict(
                            their_did=their_did,
                            my_did=my_did,
                            metadata={
                                'label': label,
                                'their_endpoint': their_endpoint,
                                'their_vk': their_vk,
                                'my_vk': my_vk,
                                'their_routing_keys': their_routing_keys,
                                'connection_key': msg.data['connection~sig']['signer']
                            }
                        )
                        pairwise = await self.get_wallet().get_pairwise(their_did)
                        if pairwise:
                            await self.get_wallet().set_pairwise_metadata(their_did, creation_kwargs['metadata'])
                            await self.__log_pairwise_update(creation_kwargs)
                        else:
                            await self.get_wallet().create_pairwise(**creation_kwargs)
                            await self.__log_pairwise_creation(creation_kwargs)
                        # Send ACK
                        please_ack = AckMessage.extract_please_ack(msg)
                        if please_ack:
                            ack = AckMessage.build(thread_id=msg.id)
                        else:
                            ack = TrustPing.Ping.build(comment='Connection established', response_requested=False)
                        await ConnectionProtocol.send_message_to_agent(their_did, ack, self.get_wallet())
                        await self.__log('Send', ack.to_dict())
                        await self.done()
                elif err_msg:
                    their_did = msg.context.get('from_did')
                    if their_did:
                        await ConnectionProtocol.send_message_to_agent(their_did, err_msg, self.get_wallet())
                        await self.__log('Send report problem', err_msg.to_dict())
                    logging.error('Validation error while parsing message: %s', msg.as_json())
                else:
                    logging.error('Validation error while parsing message: %s', msg.as_json())
            else:
                raise ErrorStatus()
