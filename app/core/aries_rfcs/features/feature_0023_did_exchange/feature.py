import re
import json
import uuid
import time
import struct
import logging
import base64

import indy.crypto
import core.indy_sdk_utils as indy_sdk_utils
from core.base import MessageFeature, FeatureMeta, WriteOnlyChannel, EndpointTransport
from core.messages.did_doc import DIDDoc
from core.messages.message import Message
from core.messages.errors import ValidationException as MessageValidationException
from core.serializer.json_serializer import JSONSerializer as Serializer
from core.wallet import WalletAgent, InvokableStateMachineMeta, WalletConnection
from state_machines.base import BaseStateMachine
from core.aries_rfcs.features.feature_0095_basic_message.feature import BasicMessage
from transport.const import WIRED_CONTENT_TYPES
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
    PROBLEM_REPORT = 'problem_report'
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
        # await WalletAgent.add_wallet_record(agent_name, pass_phrase, 'connection_key', connection_key, connection_key)
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

    @classmethod
    async def handle_message(cls, agent_name: str, msg: Message):
        # TODO: invoke state machine and handle error messages
        pass

    @staticmethod
    def build_problem_report_for_connections(problem_code, problem_str, thread_id: str=None) -> Message:
        initialized = {
            "@type": "{}/problem_report".format(DIDExchange.FAMILY),
            "problem-code": problem_code,
            "explain": problem_str
        }
        if thread_id:
            initialized['~thread'] = {Message.THREAD_ID: thread_id, Message.SENDER_ORDER: 0}
        return Message(initialized)

    @staticmethod
    async def validate_common_message_blocks(msg: Message):
        try:
            msg.validate_common_blocks()
            return True, None
        except MessageValidationException as e:
            logging.exception('Validation error while parsing message: %s' % msg.as_json())
            their_did = msg.context.get('from_did')
            if their_did:
                err_msg = DIDExchange.build_problem_report_for_connections(
                    e.error_code,
                    str(e.exception),
                    thread_id=msg.id
                )
                return False, err_msg
            else:
                return False, None
        except Exception as e:
            logging.exception('Validation error while parsing message: %s' % str(e))
            return False, None

    @staticmethod
    async def send_message_to_agent(to_did: str, msg: Message, wallet: WalletConnection):
        their_did = to_did
        pairwise_info = await wallet.get_pairwise(their_did)
        pairwise_meta = pairwise_info['metadata']
        my_did = pairwise_info['my_did']
        their_endpoint = pairwise_meta['their_endpoint']
        their_vk = pairwise_meta['their_vk']
        my_vk = await wallet.key_for_local_did(my_did)
        await DIDExchange.send_message_to_endpoint_and_key(their_vk, their_endpoint, msg, wallet, my_vk)

    @staticmethod
    async def send_message_to_endpoint_and_key(their_ver_key: str, their_endpoint: str, msg: Message,
                                               wallet: WalletConnection, my_ver_key: str=None):
        # If my_ver_key is omitted, anon-crypt is used inside pack.
        try:
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
        msg = Serializer.deserialize(unpacked['message'])
        msg.context = {
            'from_did': from_did,  # Could be None
            'to_did': to_did,  # Could be None
            'from_key': from_key,  # Could be None
            'to_key': to_key
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
            self.status = DIDExchangeStatus.Invited
            self.label = None
            self.endpoint = None

        async def handle(self, content_type, data):
            if content_type == DIDExchange.MESSAGE_CONTENT_TYPE:
                kwargs = json.loads(data)
                msg = Message(**kwargs)
            elif content_type in WIRED_CONTENT_TYPES:
                msg = await DIDExchange.unpack_agent_message(data, self.get_wallet())
            else:
                raise RuntimeError('Unknown content_type "%s"' % content_type)
            if msg.type == DIDExchange.REQUEST:
                await self.__handle_connection_request(msg)
            elif msg.type == DIDExchange.RESPONSE:
                pass

        async def __handle_connection_request(self, msg: Message):
            if self.status == DIDExchangeStatus.Invited:
                success, err_msg = await DIDExchange.validate_common_message_blocks(msg)
                if success:
                    try:
                        DIDExchange.Request.validate(msg)
                    except Exception as e:
                        logging.exception('Error while parsing message %s with error %s' % (msg.as_json(), str(e)))
                        vk, endpoint = BasicMessage.extract_verkey_endpoint(msg, DIDExchange.CONNECTION)
                        if None in (vk, endpoint):
                            # Cannot extract verkey and endpoint hence won't send any message back.
                            logging.error('Encountered error parsing connection request %s' % str(e))
                        else:
                            # Sending an error message back to the sender
                            err_msg = DIDExchange.build_problem_report_for_connections(
                                DIDExchange.REQUEST_NOT_ACCEPTED,
                                str(e),
                                thread_id=msg.id
                            )
                            DIDExchange.send_message_to_endpoint_and_key(vk, endpoint, err_msg, self.get_wallet())
                    else:
                        try:
                            connection_key = msg.context['to_key']
                            label = msg['label']
                            their_did, their_vk, their_endpoint = BasicMessage.extract_their_info(msg, DIDExchange.CONNECTION)
                            # Store their information from request
                            await indy_sdk_utils.store_their_did(self.get_wallet(), their_did, their_vk)
                            await self.get_wallet().set_did_metadata(
                                their_did,
                                metadata=dict(label=label, endpoint=their_endpoint)
                            )
                            my_did, my_vk = await indy_sdk_utils.create_and_store_my_did(self.get_wallet())
                            await self.get_wallet().create_pairwise(
                                their_did,
                                my_did,
                                {
                                    'label': label,
                                    'req_id': msg['@id'],
                                    'their_endpoint': their_endpoint,
                                    'their_vk': their_vk,
                                    'my_vk': my_vk,
                                    'connection_key': connection_key  # used to sign the response
                                }
                            )
                        except Exception as e:
                            logging.exception('Error while process invitee request')
                            raise
                        else:
                            await self.__send_connection_response(their_did)
                            self.status = DIDExchangeStatus.Requested
                elif err_msg:
                    their_did = msg.context.get('from_did')
                    if their_did:
                        await DIDExchange.send_message_to_agent(their_did, err_msg)
                    logging.error('Validation error while parsing message: %s', msg.as_json())
                else:
                    logging.error('Validation error while parsing message: %s', msg.as_json())
            else:
                raise ErrorStatus()

        async def __send_connection_response(self, their_did: str):
            pairwise_info = await self.get_wallet().get_pairwise(their_did)
            pairwise_meta = pairwise_info['metadata']
            my_did = pairwise_info['my_did']
            my_vk = await self.get_wallet().key_for_local_did(my_did)
            response_msg = DIDExchange.Response.build(pairwise_meta['req_id'], my_did, my_vk, self.endpoint)
            # Apply signature to connection field, sign it with the key used in the invitation and request
            response_msg['connection~sig'] = \
                await DIDExchange.sign_agent_message_field(
                    self.get_wallet(),
                    response_msg['connection'],
                    pairwise_meta["connection_key"]
                )
            del response_msg['connection']
            await DIDExchange.send_message_to_agent(their_did, response_msg, self.get_wallet())
        pass

    class InviteeStateMachine(BaseStateMachine, metaclass=InvokableStateMachineMeta):

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.status = DIDExchangeStatus.Null
            self.label = None
            self.endpoint = None

        async def handle(self, content_type, data):
            if content_type == DIDExchange.MESSAGE_CONTENT_TYPE:
                kwargs = json.loads(data)
                msg = Message(**kwargs)
            elif content_type in WIRED_CONTENT_TYPES:
                msg = await DIDExchange.unpack_agent_message(data, self.get_wallet())
            else:
                raise RuntimeError('Unknown content_type "%s"' % content_type)
            if msg.type == DIDExchange.INVITE:
                await self.__receive_invitation(msg)
            elif msg.type == DIDExchange.RESPONSE:
                await self.__handle_connection_response(msg)

        async def __receive_invitation(self, invitation: Message):
            if self.status == DIDExchangeStatus.Null:
                self.status = DIDExchangeStatus.Invited
                await self.get_wallet().add_wallet_record(
                    'invitations',
                    invitation['recipientKeys'][0],
                    invitation.as_json()
                )
                await self.__handle_connection_request(invitation)
                self.status = DIDExchangeStatus.Requested
            elif self.status == DIDExchangeStatus.Invited:
                # No change (Resend or new invite that supersedes)
                pass
            elif self.status == DIDExchangeStatus.Requested:
                # NewRelationship
                pass
            else:
                raise ImpossibleStatus()

        async def __handle_connection_request(self, invitation: Message):
            """Connection Request"""
            if self.status == DIDExchangeStatus.Null:
                raise ImpossibleStatus()
            elif self.status == DIDExchangeStatus.Invited:
                their = dict(
                    label=invitation['label'],
                    connection_key=invitation['recipientKeys'][0],
                    endpoint=invitation['serviceEndpoint']
                )
                # Create my information for connection
                my_did, my_vk = await indy_sdk_utils.create_and_store_my_did(self.get_wallet())
                await self.get_wallet().set_did_metadata(my_did, their)
                # Send Connection Request to inviter
                request = DIDExchange.Request.build(self.label, my_did, my_vk, self.endpoint)
                try:
                    wire_message = await self.get_wallet().pack_message(
                        message=Serializer.serialize(request).decode('utf-8'),
                        their_ver_key=their['connection_key'],
                        my_ver_key=my_vk
                    )
                    transport = EndpointTransport(address=their['endpoint'])
                    await transport.send_wire_message(wire_message)
                except Exception as e:
                    logging.exception(str(e))
                    raise
            elif self.status == DIDExchangeStatus.Requested:
                # No change (Resend or req that supersedes)
                pass
            elif self.status == DIDExchangeStatus.Responded:
                # Resend (may indicate that out conn resp wasn't received)?
                pass
            else:
                raise ErrorStatus()

        async def __handle_connection_response(self, msg: Message):
            if self.status == DIDExchangeStatus.Requested:
                success, err_msg = await DIDExchange.validate_common_message_blocks(msg)
                if success:
                    my_did = msg.context['to_did']
                    if my_did is None:
                        msg[DIDExchange.CONNECTION], sig_verified = \
                            await self.agent.unpack_and_verify_signed_agent_message_field(msg['connection~sig'])
                        if not sig_verified:
                            logging.error('Encountered error parsing connection response. Connection request not found.')
                        else:
                            vk, endpoint = BasicMessage.extract_verkey_endpoint(msg)
                            if None in (vk, endpoint):
                                # Cannot extract verkey and endpoint hence won't send any message back.
                                logging.error('Encountered error parsing connection response. Connection request not found.')
                            else:
                                # Sending an error message back to the sender
                                err_msg = DIDExchange.build_problem_report_for_connections(
                                    DIDExchange.RESPONSE_FOR_UNKNOWN_REQUEST,
                                    "No corresponding connection request found",
                                    thread_id=msg.id
                                )
                                await DIDExchange.send_message_to_endpoint_and_key(vk, endpoint, err_msg)
                    else:
                        # Following should return an error if key not found for given DID
                        my_vk = await self.get_wallet().key_for_local_did(my_did)
                        # process signed field
                        msg[DIDExchange.CONNECTION], sig_verified = \
                            await DIDExchange.unpack_and_verify_signed_agent_message_field(msg['connection~sig'])
                        their_did, their_vk, their_endpoint = BasicMessage.extract_their_info(msg, DIDExchange.CONNECTION)
                        # Verify that their_vk (from did doc) matches msg_vk
                        msg_vk = msg.context['from_key']
                        if their_vk != msg_vk:
                            err_msg = \
                                DIDExchange.build_problem_report_for_connections(
                                    DIDExchange.KEY_ERROR,
                                    "Key provided in response does not match expected key",
                                    thread_id=msg.id
                                )
                            verkey, endpoint = BasicMessage.extract_verkey_endpoint(msg, DIDExchange.CONNECTION)
                            logging.error("Key provided in response does not match expected key")
                            await DIDExchange.send_message_to_endpoint_and_key(verkey, endpoint, err_msg)
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
                                'endpoint': their_endpoint
                            }
                        )
                        # Create pairwise relationship between my did and their did
                        await self.get_wallet().create_pairwise(
                            their_did,
                            my_did,
                            {
                                'label': label,
                                'their_endpoint': their_endpoint,
                                'their_vk': their_vk,
                                'my_vk': my_vk,
                                'connection_key': msg.data['connection~sig']['signer']
                            }
                        )
                elif err_msg:
                    their_did = msg.context.get('from_did')
                    if their_did:
                        await DIDExchange.send_message_to_agent(their_did, err_msg)
                    logging.error('Validation error while parsing message: %s', msg.as_json())
                else:
                    logging.error('Validation error while parsing message: %s', msg.as_json())
            else:
                raise ErrorStatus()
