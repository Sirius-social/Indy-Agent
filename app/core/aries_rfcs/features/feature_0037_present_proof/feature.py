import re
import json
import uuid
import base64
import logging
from typing import List
from collections import UserDict

from indy.anoncreds import generate_nonce
from django.conf import settings

import core.indy_sdk_utils as indy_sdk_utils
import core.codec
import core.const
import core.ledger
from core.models import get_issuer_schema, get_cred_def_meta
from core.proofs import verifier_verify_proof
from core.base import WireMessageFeature, FeatureMeta, EndpointTransport, WriteOnlyChannel
from core.messages.message import Message
from core.messages.errors import ValidationException as MessageValidationException
from core.serializer.json_serializer import JSONSerializer as Serializer
from core.wallet import WalletAgent, InvokableStateMachineMeta, WalletConnection
from state_machines.base import BaseStateMachine, MachineIsDone
from core.aries_rfcs.features.feature_0015_acks.feature import AckMessage
from core.aries_rfcs.concepts.concept_0094_cross_domain.concept import RoutingMessage
from transport.const import WIRED_CONTENT_TYPES

from .statuses import *
from .errors import *


class ProposedAttrib(UserDict):

    def __init__(self, name: str, value: str=None, mime_type: str=None, referent: str=None, cred_def_id: str=None):
        super().__init__()
        self.data['name'] = name
        if mime_type:
            self.data['mime-type'] = mime_type
        if value:
            self.data['value'] = value
        if referent:
            self.data['referent'] = referent
        if cred_def_id:
            self.data['cred_def_id'] = cred_def_id

    def to_json(self):
        return self.data


class ProposedPredicate(UserDict):

    def __init__(self, name: str, predicate: str, threshold, cred_def_id: str=None):
        super().__init__()
        self.data['name'] = name
        self.data['predicate'] = predicate
        self.data['threshold'] = threshold
        if cred_def_id:
            self.data['cred_def_id'] = cred_def_id

    def to_json(self):
        return self.data


class AttribTranslation(UserDict):

    def __init__(self, attrib_name: str, translation: str, **kwargs):
        super().__init__()
        self.data['attrib_name'] = attrib_name
        self.data['translation'] = translation

    def to_json(self):
        return self.data


class Context:

    def __init__(self):
        self.my_did = None
        self.their_did = None
        self.my_ver_key = None
        self.their_verkey = None
        self.their_endpoint = None
        self.their_routing_keys = None


class PresentProofProtocol(WireMessageFeature, metaclass=FeatureMeta):
    """https://github.com/hyperledger/aries-rfcs/tree/master/features/0037-present-proof"""

    DEF_LOCALE = 'en'
    FAMILY_NAME = "present-proof"
    VERSION = "1.0"
    FAMILY = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/" + FAMILY_NAME + "/" + VERSION

    """Messages"""
    # Verifier send to Prover message describes values that need to be revealed and predicates that need to be fulfilled
    REQUEST_PRESENTATION = FAMILY + "/request-presentation"
    # This message is a response to a Presentation Request message and contains signed presentations.
    PRESENTATION = FAMILY + "/presentation"
    #
    PROBLEM_REPORT = FAMILY + "/problem_report"
    # This is not a message but an inner object for other messages in this protocol.
    # It is used to construct a preview of the data for the presentation.
    PRESENTATION_PREVIEW_TYPE = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/present-proof/1.0/presentation-preview"
    # extended
    CREDENTIAL_TRANSLATION_TYPE = "https://github.com/Sirius-social/agent/tree/master/messages/credential-translation"
    CREDENTIAL_TRANSLATION_ID = "credential-translation"

    """Problem reports"""
    PROPOSE_NOT_ACCEPTED = "propose_not_accepted"
    RESPONSE_NOT_ACCEPTED = "response_not_accepted"
    REQUEST_NOT_ACCEPTED = "request_not_accepted"
    RESPONSE_FOR_UNKNOWN_REQUEST = "response_for_unknown_request"
    REQUEST_PROCESSING_ERROR = 'request_processing_error'
    VERIFY_ERROR = 'verify_error'

    STATE_MACHINE_TTL = 60  # 60 sec
    CMD_START = 'start'
    CMD_STOP = 'stop'
    MESSAGE_CONTENT_TYPE = 'application/json'
    WIRED_CONTENT_TYPE = WIRED_CONTENT_TYPES[0]

    @classmethod
    def endorsement(cls, msg: Message) -> bool:
        if msg.type == AckMessage.ACK:
            return True
        if msg.type == PresentProofProtocol.PROBLEM_REPORT:
            return True
        matches = re.match("(.+/.+/\d+.\d+).+", msg.type)
        if matches:
            family = matches.group(1)
            return family in cls.FAMILY
        return False

    @classmethod
    async def handle(cls, agent_name: str, wire_message: bytes, my_label: str = None, my_endpoint: str = None) -> bool:
        unpacked = await WalletAgent.unpack_message(agent_name, wire_message)
        kwargs = json.loads(unpacked['message'])
        message = Message(**kwargs)
        if message.get('@type', None) is None:
            return False
        if not cls.endorsement(message):
            return False
        state_machine_id = cls.get_state_machine_id(unpacked['sender_verkey'])
        if message.type in [PresentProofProtocol.REQUEST_PRESENTATION, AckMessage.ACK]:
            if message.type == PresentProofProtocol.REQUEST_PRESENTATION:
                machine_class = PresentProofProtocol.ProverStateMachine
                await WalletAgent.start_state_machine(
                    status=PresentProofStatus.Null, ttl=PresentProofProtocol.STATE_MACHINE_TTL,
                    agent_name=agent_name, machine_class=machine_class, machine_id=state_machine_id
                )
            await WalletAgent.invoke_state_machine(
                agent_name=agent_name, id_=state_machine_id,
                content_type=cls.WIRED_CONTENT_TYPE, data=wire_message
            )
            return True
        elif message.type in [PresentProofProtocol.PRESENTATION]:
            await WalletAgent.invoke_state_machine(
                agent_name=agent_name, id_=state_machine_id,
                content_type=cls.WIRED_CONTENT_TYPE, data=wire_message
            )
            return True
        elif message.type == PresentProofProtocol.PROBLEM_REPORT:
            await WalletAgent.invoke_state_machine(
                agent_name=agent_name, id_=state_machine_id,
                content_type=cls.WIRED_CONTENT_TYPE, data=wire_message
            )
            return True
        else:
            return False

    @staticmethod
    def get_state_machine_id(key: str):
        return 'proof-request:' + key

    @classmethod
    def build_problem_report_for_connections(cls, problem_code, problem_str, thread_id: str = None) -> Message:
        initialized = {
            "@type": "{}/problem_report".format(cls.FAMILY),
            "problem-code": problem_code,
            "explain": problem_str
        }
        if thread_id:
            initialized['~thread'] = {Message.THREAD_ID: thread_id, Message.SENDER_ORDER: 0}
        return Message(initialized)

    @staticmethod
    async def send_problem_report(
            wallet: WalletConnection, problem_code: str, problem_str: str, context: Context, thread_id: str = None
    ):
        err_msg = PresentProofProtocol.build_problem_report_for_connections(
            problem_code,
            problem_str,
            thread_id
        )
        try:
            if context.their_routing_keys:
                wire_message = await RoutingMessage.pack(
                    err_msg,
                    wallet,
                    context.their_verkey,
                    context.their_routing_keys,
                    context.my_ver_key
                )
            else:
                wire_message = await wallet.pack_message(
                    Serializer.serialize(err_msg).decode('utf-8'),
                    context.their_verkey,
                    context.my_ver_key
                )
        except Exception as e:
            logging.exception(str(e))
            raise
        else:
            transport = EndpointTransport(address=context.their_endpoint)
            await transport.send_wire_message(wire_message)
            return err_msg

    @classmethod
    async def validate_common_message_blocks(cls, msg: Message, problem_code: str, context: Context):
        try:
            msg.validate_common_blocks()
            return True, None
        except MessageValidationException as e:
            logging.exception('Validation error while parsing message: %s' % msg.as_json())
            if context.their_did:
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
            wallet: WalletConnection, my_ver_key: str = None, their_routing_keys: list = None
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
        their_endpoint = None
        their_routing_keys = None
        context = Context()
        if 'sender_verkey' in unpacked:
            from_key = unpacked['sender_verkey']
            from_did = await indy_sdk_utils.did_for_key(wallet, unpacked['sender_verkey'])
            pairwise_info = await wallet.get_pairwise(from_did)
            pairwise_meta = pairwise_info['metadata']
            their_endpoint = pairwise_meta['their_endpoint']
            their_routing_keys = pairwise_meta.get('their_routing_keys', None)
        to_key = unpacked['recipient_verkey']
        to_did = await indy_sdk_utils.did_for_key(wallet, unpacked['recipient_verkey'])

        msg = Serializer.deserialize(unpacked['message'])

        context.their_did = from_did
        context.my_did = to_did
        context.my_ver_key = to_key
        context.their_verkey = from_key
        context.their_endpoint = their_endpoint
        context.their_routing_keys = their_routing_keys

        return msg, context

    class VerifierStateMachine(BaseStateMachine, metaclass=InvokableStateMachineMeta):

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.status = PresentProofStatus.Null
            self.to = None
            self.comment = None
            self.locale = None
            self.log_channel_name = None
            self.enable_propose = None
            self.proof_request_buffer = None
            self.__log_channel = None

        @classmethod
        async def start_verifying(
                cls, agent_name: str, pass_phrase: str, to: str, proof_request: dict,
                translation: List[AttribTranslation]=None,
                comment: str=None, locale: str=None, enable_propose: bool=False, ttl: int=None
        ):
            machine_class = PresentProofProtocol.VerifierStateMachine
            log_channel_name = 'present-proof-log/' + uuid.uuid4().hex

            to_verkey = await WalletAgent.key_for_local_did(
                agent_name, pass_phrase, to
            )
            if not to_verkey:
                raise RuntimeError('Unknown pairwise for DID: %s' % str(to))
            state_machine_id = PresentProofProtocol.get_state_machine_id(to_verkey)
            await WalletAgent.start_state_machine(
                agent_name=agent_name, machine_class=machine_class, machine_id=state_machine_id,
                status=PresentProofStatus.Null, ttl=ttl or PresentProofProtocol.STATE_MACHINE_TTL,
                to=to, log_channel_name=log_channel_name, enable_propose=enable_propose
            )

            data = dict(
                command=PresentProofProtocol.CMD_START,
                comment=comment,
                locale=locale,
                proof_request=proof_request,
                translation=[t.to_json() for t in translation] if translation else None
            )
            await WalletAgent.invoke_state_machine(
                agent_name=agent_name,
                id_=state_machine_id,
                content_type=PresentProofProtocol.MESSAGE_CONTENT_TYPE,
                data=data
            )
            return log_channel_name

        @classmethod
        async def stop_verifying(cls, agent_name: str, pass_phrase: str, to: str):
            to_verkey = await WalletAgent.key_for_local_did(
                agent_name, pass_phrase, to
            )
            if not to_verkey:
                raise RuntimeError('Unknown pairwise for DID: %s' % str(to))
            state_machine_id = PresentProofProtocol.get_state_machine_id(to_verkey)
            data = dict(
                command=PresentProofProtocol.CMD_STOP,
            )
            await WalletAgent.invoke_state_machine(
                agent_name=agent_name,
                id_=state_machine_id,
                content_type=PresentProofProtocol.MESSAGE_CONTENT_TYPE,
                data=data
            )

        async def handle(self, content_type, data):
            try:
                if content_type == PresentProofProtocol.MESSAGE_CONTENT_TYPE:
                    command = str(data.get('command', None))
                    if command == PresentProofProtocol.CMD_START:
                        await self.__log('Start verifying', data)
                        # Store Context
                        comment = data.get('comment', None)
                        locale = data.get('locale', None) or PresentProofProtocol.DEF_LOCALE
                        proof_request = data['proof_request']
                        self.proof_request_buffer = json.dumps(proof_request)
                        translation = data.get('translation', None)
                        translation = [AttribTranslation(**item) for item in translation] if translation else None

                        id_suffix = uuid.uuid4().hex
                        data = {
                            "@type": PresentProofProtocol.REQUEST_PRESENTATION,
                            "comment": "some comment",
                            "request_presentations~attach": [
                                {
                                    "@id": "libindy-request-presentation-" + id_suffix,
                                    "mime-type": "application/json",
                                    "data": {
                                        "base64": base64.b64encode(json.dumps(proof_request).encode()).decode()
                                    }
                                }
                            ]
                        }

                        if comment:
                            data['comment'] = comment
                            data['~l10n'] = {"locale": locale}
                            self.comment = comment
                            self.locale = locale

                        if translation:
                            data['~attach'] = [
                                {
                                    "@type": PresentProofProtocol.CREDENTIAL_TRANSLATION_TYPE,
                                    "id": PresentProofProtocol.CREDENTIAL_TRANSLATION_ID,
                                    '~l10n': {"locale": locale},
                                    "mime-type": "application/json",
                                    "data": {
                                        "json": [trans.to_json() for trans in translation]
                                    }
                                }
                            ]

                        message_request = Message(data)
                        await PresentProofProtocol.send_message_to_agent(self.to, message_request, self.get_wallet())
                        self.status = PresentProofStatus.RequestSent
                        await self.__log(event='Send Request-Presentation', details=data)

                    elif command == PresentProofProtocol.CMD_STOP:
                        if self.to and self.status != PresentProofStatus.Null:
                            err_msg = PresentProofProtocol.build_problem_report_for_connections(
                                problem_code=PresentProofProtocol.REQUEST_NOT_ACCEPTED,
                                problem_str='Actor unexpected stopped issuing',
                            )
                            await PresentProofProtocol.send_message_to_agent(self.to, err_msg, self.get_wallet())
                        await self.__log('Actor unexpected stopped issuing')
                        await self.done()
                    else:
                        raise RuntimeError('Unknown command: %s' % command)
                elif content_type in WIRED_CONTENT_TYPES:
                    msg, context = await PresentProofProtocol.unpack_agent_message(data, self.get_wallet())
                    success, err_msg = await PresentProofProtocol.validate_common_message_blocks(
                        msg,
                        PresentProofProtocol.REQUEST_NOT_ACCEPTED,
                        context
                    )
                    if not success and err_msg:
                        await PresentProofProtocol.send_message_to_agent(context.their_did, err_msg, self.get_wallet())
                    if msg.type == PresentProofProtocol.PRESENTATION:
                        await self.__log('Received presentation', msg.to_dict())
                        if self.status == PresentProofStatus.RequestSent:
                            presentation_attach = msg['presentations~attach']
                            if isinstance(presentation_attach, list):
                                presentation_attach = presentation_attach[0]
                            payload = json.loads(
                                base64.b64decode(
                                    presentation_attach['data']['base64']
                                ).decode()
                            )
                            proof = payload
                            await self.__log(core.const.PROOF, proof)
                            schemas = dict()
                            cred_defs = dict()

                            for ident in proof['identifiers']:
                                schema_id = ident['schema_id']
                                cred_def_id = ident['cred_def_id']
                                schema = await indy_sdk_utils.get_issuer_schema(self.get_wallet(), schema_id) or await get_issuer_schema(schema_id)
                                if schema:
                                    schemas[schema_id] = schema
                                else:
                                    _, schema = await core.ledger.get_schema(context.my_did, schema_id)
                                schemas[schema_id] = schema
                                cred_def = await indy_sdk_utils.get_cred_def(self.get_wallet(), cred_def_id) or await self.__get_cred_def_body(cred_def_id)
                                if cred_def:
                                    cred_defs[cred_def_id] = cred_def
                                else:
                                    _, cred_def = await core.ledger.get_cred_def(context.my_did, cred_def_id)
                                    indy_sdk_utils.store_cred_def(self.get_wallet(), cred_def_id, cred_def)
                                cred_defs[cred_def_id] = cred_def

                            await self.__log('schemas', schemas)
                            await self.__log('cred_defs', cred_defs)

                            success, error_message = await verifier_verify_proof(
                                proof_request=json.loads(self.proof_request_buffer),
                                proof=proof,
                                schemas=schemas,
                                credential_defs=cred_defs,
                                rev_reg_defs=None,
                                rev_regs=None
                            )
                            await self.__log('verify result', dict(success=success, error_message=error_message))
                            if success:
                                ack = AckMessage.build(msg.id)
                                await PresentProofProtocol.send_message_to_agent(
                                    self.to, ack, self.get_wallet()
                                )
                                await self.__log(event='Send Ack', details=ack.to_dict())
                                await self.__log(event=core.const.VERIFY_SUCCESS)
                            else:
                                await self.__send_problem_report(
                                    problem_code=PresentProofProtocol.VERIFY_ERROR,
                                    problem_str=error_message or 'Proof verification finished with errors',
                                    context=context,
                                    thread_id=msg.id
                                )
                                await self.__log(core.const.VERIFY_ERROR)
                            await self.done()

                        else:
                            await self.__send_problem_report(
                                problem_code=PresentProofProtocol.RESPONSE_NOT_ACCEPTED,
                                problem_str='Impossible state',
                                context=context,
                                thread_id=msg.id
                            )
                            raise ImpossibleStatus()
                    elif msg.type == PresentProofProtocol.PROBLEM_REPORT:
                        await self.__log('Received problem report', msg.to_dict())
                        await self.done()
                    else:
                        await self.__send_problem_report(
                            problem_code=PresentProofProtocol.RESPONSE_FOR_UNKNOWN_REQUEST,
                            problem_str='Unknown message type',
                            context=context,
                            thread_id=msg.id
                        )
            except Exception as e:
                if not isinstance(e, MachineIsDone):
                    print('------------- FEATURE 0037 --------------')
                    print('Exception')
                    print(str(e))
                    print('----------------------------------------')
                    logging.exception('Base machine terminated with exception: %s' % str(e))
                await self.done()

        async def done(self):
            if self.__log_channel is not None:
                await self.__log('Done')
                await self.__log_channel.close()
            await self.__log('Done')
            await super().done()

        async def __send_problem_report(self, problem_code: str, problem_str: str, context: Context, thread_id: str = None):
            err_msg = await PresentProofProtocol.send_problem_report(
                self.get_wallet(),
                problem_code,
                problem_str,
                context,
                thread_id
            )
            await self.__log('Send report problem', err_msg.to_dict())

        @staticmethod
        async def __get_cred_def_body(cred_def_id: str):
            meta = await get_cred_def_meta(cred_def_id)
            if meta:
                return meta.get('cred_def', None)
            else:
                return None

        async def __log(self, event: str, details: dict=None):
            event_message = '%s (%s)' % (event, self.get_id())
            print('------ %s --------' % event)
            if details:
                print(json.dumps(details, indent=2, sort_keys=True))
            await self.get_wallet().log(message=event_message, details=details)
            if self.__log_channel is None:
                self.__log_channel = await WriteOnlyChannel.create(self.log_channel_name)
            if not self.__log_channel.is_closed:
                await self.__log_channel.write([event_message, details])

    class ProverStateMachine(BaseStateMachine, metaclass=InvokableStateMachineMeta):

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.status = PresentProofStatus.Null
            self.to = None
            self.ack_message_id = None

        async def handle(self, content_type, data):
            try:
                if content_type in WIRED_CONTENT_TYPES:
                    msg, context = await PresentProofProtocol.unpack_agent_message(data, self.get_wallet())
                    self.to = context.their_did
                    success, err_msg = await PresentProofProtocol.validate_common_message_blocks(
                        msg,
                        PresentProofProtocol.REQUEST_NOT_ACCEPTED,
                        context
                    )
                    if not success and err_msg:
                        await PresentProofProtocol.send_message_to_agent(
                            context.their_did, err_msg, self.get_wallet()
                        )
                else:
                    raise RuntimeError('Unsupported content_type "%s"' % content_type)
                if msg.type == PresentProofProtocol.REQUEST_PRESENTATION:
                    if self.status == PresentProofStatus.Null:
                        await self.__log('Received request presentation', msg.to_dict())

                        request_attach = msg['request_presentations~attach']
                        if isinstance(request_attach, list):
                            request_attach = request_attach[0]
                        payload = json.loads(
                            base64.b64decode(
                                request_attach['data']['base64']
                            ).decode()
                        )
                        proof_request = payload
                        nonce = proof_request.get('nonce', None)
                        if not nonce:
                            proof_request['nonce'] = await generate_nonce()

                        search_handle = await self.get_wallet().prover_search_credentials_for_proof_req(
                            proof_request=proof_request
                        )
                        try:
                            requested_attributes = proof_request.get('requested_attributes', {})
                            requested_predicates = proof_request.get('requested_predicates', {})
                            schemas_json = dict()
                            cred_defs_json = dict()
                            prover_requested_creds = {
                                'self_attested_attributes': {},
                                'requested_attributes': {},
                                'requested_predicates': {}
                            }
                            for attr_referent in requested_attributes.keys():
                                cred_for_attr = await self.get_wallet().prover_fetch_credentials_for_proof_req(
                                    search_handle=search_handle,
                                    item_referent=attr_referent,
                                    count=1
                                )
                                if cred_for_attr:
                                    cred_info = cred_for_attr[0]['cred_info']
                                    schema_id = cred_info['schema_id']
                                    schemas_json[schema_id] = await indy_sdk_utils.get_issuer_schema(
                                        self.get_wallet(), schema_id
                                    )
                                    cred_def_id = cred_info['cred_def_id']
                                    cred_defs_json[cred_def_id] = await indy_sdk_utils.get_cred_def(
                                        self.get_wallet(), cred_def_id
                                    )
                                    prover_requested_creds['requested_attributes'][attr_referent] = {
                                        'cred_id': cred_info['referent'],
                                        'revealed': True
                                    }
                            for pred_referent in requested_predicates.keys():
                                cred_for_predicate = await self.get_wallet().prover_fetch_credentials_for_proof_req(
                                    search_handle=search_handle,
                                    item_referent=pred_referent,
                                    count=1
                                )
                                if cred_for_predicate:
                                    cred_info = cred_for_predicate[0]['cred_info']
                                    schema_id = cred_info['schema_id']
                                    schemas_json[schema_id] = await indy_sdk_utils.get_issuer_schema(
                                        self.get_wallet(), schema_id
                                    )
                                    cred_def_id = cred_info['cred_def_id']
                                    cred_defs_json[cred_def_id] = await indy_sdk_utils.get_cred_def(
                                        self.get_wallet(), cred_def_id
                                    )
                                    prover_requested_creds['requested_predicates'][pred_referent] = {
                                        'cred_id': cred_info['referent'],
                                    }

                        finally:
                            await self.get_wallet().prover_close_credentials_search_for_proof_req(search_handle)

                        master_secret_name = settings.INDY['WALLET_SETTINGS']['PROVER_MASTER_SECRET_NAME']
                        proof = await self.get_wallet().prover_create_proof(
                            proof_req=proof_request,
                            requested_creds=prover_requested_creds,
                            link_secret_id=master_secret_name,
                            schemas=schemas_json,
                            cred_defs=cred_defs_json,
                            rev_states=None
                        )

                        self.ack_message_id = uuid.uuid4().hex
                        data = {
                            "@type": PresentProofProtocol.PRESENTATION,
                            "@id": self.ack_message_id,
                            "presentations~attach": [
                                {
                                    "@id": "libindy-presentation-" + self.ack_message_id,
                                    "mime-type": "application/json",
                                    "data": {
                                        "base64": base64.b64encode(json.dumps(proof).encode()).decode()
                                    }
                                }
                            ]
                        }
                        message_proof = Message(data)
                        await PresentProofProtocol.send_message_to_agent(self.to, message_proof, self.get_wallet())
                        self.status = PresentProofStatus.PresentationSent
                        await self.__log(event='Send Proof', details=data)
                    else:
                        await self.__send_problem_report(
                            problem_code=PresentProofProtocol.REQUEST_PROCESSING_ERROR,
                            problem_str='Impossible state machine state',
                            context=context,
                            thread_id=msg.id
                        )
                        raise ImpossibleStatus
                elif msg.type == AckMessage.ACK:
                    await self.__log('Received ack', msg.to_dict())
                    if self.status == PresentProofStatus.PresentationSent:
                        await self.done()
                    else:
                        await self.__send_problem_report(
                            problem_code=PresentProofProtocol.RESPONSE_NOT_ACCEPTED,
                            problem_str='UnExpected message type for status',
                            context=context,
                            thread_id=msg.id
                        )
                        raise ImpossibleStatus
                elif msg.type == PresentProofProtocol.PROBLEM_REPORT:
                    await self.__log('Received problem report', msg.to_dict())
                    await self.done()
                else:
                    await self.__send_problem_report(
                        problem_code=PresentProofProtocol.RESPONSE_FOR_UNKNOWN_REQUEST,
                        problem_str='Unknown message type',
                        context=context,
                        thread_id=msg.id
                    )
            except Exception as e:
                if not isinstance(e, MachineIsDone):
                    logging.exception('Base machine terminated with exception')
                await self.done()

        async def done(self):
            await self.__log('Done')
            await super().done()

        async def __send_problem_report(self, problem_code: str, problem_str: str, context: Context, thread_id: str=None):
            err_msg = await PresentProofProtocol.send_problem_report(
                self.get_wallet(),
                problem_code,
                problem_str,
                context,
                thread_id
            )
            await self.__log('Send report problem', err_msg.to_dict())

        @staticmethod
        def __restore_schema_json(schema_id: str, attribs: dict):
            did_issuer, proto_ver, name, version = schema_id.split(':')
            return {
                'name': name,
                'version': version,
                'attributes': ["age", "sex", "height", "name"]
            }

        async def __log(self, event: str, details: dict = None):
            event_message = '%s (%s)' % (event, self.get_id())
            await self.get_wallet().log(message=event_message, details=details)
