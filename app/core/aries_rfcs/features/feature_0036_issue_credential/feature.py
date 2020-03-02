import re
import json
import uuid
import logging
import base64
from collections import UserDict
from typing import List, Dict, Any

import core.indy_sdk_utils as indy_sdk_utils
import core.codec
import core.const
from core.base import WireMessageFeature, FeatureMeta, EndpointTransport, WriteOnlyChannel
from core.messages.message import Message
from core.messages.errors import ValidationException as MessageValidationException
from core.serializer.json_serializer import JSONSerializer as Serializer
from core.wallet import WalletAgent, InvokableStateMachineMeta, WalletConnection
from state_machines.base import BaseStateMachine, MachineIsDone
from core.wallet import WalletOperationError
from core.aries_rfcs.features.feature_0015_acks.feature import AckMessage
from transport.const import WIRED_CONTENT_TYPES

from .statuses import *
from .errors import *


class ProposedAttrib(UserDict):

    def __init__(self, name: str, value: str, mime_type: str=None, **kwargs):
        super().__init__()
        self.data['name'] = name
        if mime_type:
            self.data['mime-type'] = mime_type
        self.data['value'] = value

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


class IssueCredentialProtocol(WireMessageFeature, metaclass=FeatureMeta):
    """https://github.com/hyperledger/aries-rfcs/tree/master/features/0036-issue-credential"""

    DEF_LOCALE = 'en'
    FAMILY_NAME = "issue-credential"
    VERSION = "1.1"
    FAMILY = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/" + FAMILY_NAME + "/" + VERSION

    """Messages"""
    # potential Holder to Issuer (optional). Tells what the Holder hopes to receive.
    PROPOSE_CREDENTIAL = FAMILY + "/propose-credential"
    # Issuer to potential Holder (optional for some credential implementations; required for Hyperledger Indy).
    # Tells what the Issuer intends to issue, and possibly, the price the Issuer expects to be paid.
    OFFER_CREDENTIAL = FAMILY + "/offer-credential"
    # Potential Holder to Issuer. If neither of the previous message types is used,
    # this is the message that begins the protocol.
    REQUEST_CREDENTIAL = FAMILY + "/request-credential"
    # Issuer to new Holder. Attachment payload contains the actual credential.
    ISSUE_CREDENTIAL = "/issue-credential"

    CREDENTIAL_PREVIEW_TYPE = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/issue-credential/1.0/credential-preview"
    CREDENTIAL_TRANSLATION_TYPE = "https://github.com/Sirius-social/agent/blob/master/messages/credential-translation"
    CREDENTIAL_TRANSLATION_ID = "credential-translation"

    """Problem reports"""
    PROBLEM_REPORT = 'problem_report'
    PROPOSE_NOT_ACCEPTED = "propose_not_accepted"
    OFFER_PROCESSING_ERROR = 'offer_processing_error'
    REQUEST_NOT_ACCEPTED = "request_not_accepted"
    ISSUE_PROCESSING_ERROR = 'issue_processing_error'
    RESPONSE_FOR_UNKNOWN_REQUEST = "response_for_unknown_request"
    # internal usage definitions
    MESSAGE_CONTENT_TYPE = 'application/json'
    WIRED_CONTENT_TYPE = WIRED_CONTENT_TYPES[0]

    @classmethod
    async def handle(cls, agent_name: str, wire_message: bytes, my_label: str = None, my_endpoint: str = None) -> bool:
        unpacked = await WalletAgent.unpack_message(agent_name, wire_message)
        kwargs = json.loads(unpacked['message'])
        message = Message(**kwargs)
        if message.get('@type', None) is None:
            return False
        state_machine_id = unpacked['sender_verkey']
        if message.type in [cls.ISSUE_CREDENTIAL, cls.OFFER_CREDENTIAL]:
            machine_class = IssueCredentialProtocol.HolderSateMachine
            if message.type == cls.OFFER_CREDENTIAL:
                await WalletAgent.start_state_machine(
                    status=IssueCredentialStatus.Null,
                    agent_name=agent_name, machine_class=machine_class, machine_id=state_machine_id
                )
            await WalletAgent.invoke_state_machine(
                agent_name=agent_name, id_=state_machine_id,
                content_type=cls.WIRED_CONTENT_TYPE, data=wire_message
            )
            return True
        elif message.type in [cls.REQUEST_CREDENTIAL, AckMessage.ACK]:
            await WalletAgent.invoke_state_machine(
                agent_name=agent_name, id_=state_machine_id,
                content_type=cls.WIRED_CONTENT_TYPE, data=wire_message
            )
            return True
        else:
            return False

    @classmethod
    def endorsement(cls, msg: Message) -> bool:
        matches = re.match("(.+/.+/\d+.\d+).+", msg.type)
        if matches:
            family = matches.group(1)
            return family in cls.FAMILY
        return False

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
            wallet: WalletConnection, problem_code: str, problem_str: str, context: Context, thread_id: str=None
    ):
        err_msg = IssueCredentialProtocol.build_problem_report_for_connections(
            problem_code,
            problem_str,
            thread_id
        )
        try:
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
        my_vk = await wallet.key_for_local_did(my_did)
        await cls.send_message_to_endpoint_and_key(their_vk, their_endpoint, msg, wallet, my_vk)

    @staticmethod
    async def send_message_to_endpoint_and_key(their_ver_key: str, their_endpoint: str, msg: Message,
                                               wallet: WalletConnection, my_ver_key: str = None):
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
        their_endpoint = None
        context = Context()
        if 'sender_verkey' in unpacked:
            from_key = unpacked['sender_verkey']
            from_did = await indy_sdk_utils.did_for_key(wallet, unpacked['sender_verkey'])
            pairwise_info = await wallet.get_pairwise(from_did)
            pairwise_meta = pairwise_info['metadata']
            their_endpoint = pairwise_meta['their_endpoint']
        to_key = unpacked['recipient_verkey']
        to_did = await indy_sdk_utils.did_for_key(wallet, unpacked['recipient_verkey'])

        msg = Serializer.deserialize(unpacked['message'])

        context.their_did = from_did
        context.my_did = to_did
        context.my_ver_key = to_key
        context.their_verkey = from_key
        context.their_endpoint = their_endpoint

        return msg, context

    @classmethod
    def propose_credential(
            cls,
            comment: str=None, locale: str=DEF_LOCALE, proposal_attrib: List[ProposedAttrib]=None, schema_id: str=None,
            schema_name: str=None, schema_version: str=None, schema_issuer_did: str=None, cred_def_id: str=None,
            issuer_did: str=None, proposal_attrib_translation: List[AttribTranslation]=None
    ):
        data = {
            '@type': cls.PROPOSE_CREDENTIAL,
            '~l10n': {"locale": locale},
        }
        if comment:
            data['comment'] = comment
        if schema_id:
            data['schema_id'] = schema_id
        if schema_name:
            data['schema_name'] = schema_name
        if schema_version:
            data['schema_version'] = schema_version
        if schema_issuer_did:
            data['schema_issuer_did'] = schema_issuer_did
        if cred_def_id:
            data['cred_def_id'] = cred_def_id
        if issuer_did:
            data['issuer_did'] = issuer_did
        if proposal_attrib:
            data['credential_proposal'] = {
                "@type": cls.CREDENTIAL_PREVIEW_TYPE,
                "attributes": [attrib.to_json() for attrib in proposal_attrib]
            }
            if proposal_attrib_translation:
                data['~attach'] = [
                    {
                        "@type": cls.CREDENTIAL_TRANSLATION_TYPE,
                        "id": cls.CREDENTIAL_TRANSLATION_ID,
                        '~l10n': {"locale": locale},
                        "mime-type": "application/json",
                        "data": {
                            "json": [trans.to_json() for trans in proposal_attrib_translation]
                        }
                    }
                ]
        return Message(data)

    class IssuerStateMachine(BaseStateMachine, metaclass=InvokableStateMachineMeta):

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.status = IssueCredentialStatus.Null
            self.ack_message_id = None
            self.cred_def_id = None
            self.rev_reg_id = None
            self.values_buffer = None
            self.cred_offer_buffer = None
            self.to = None
            self.comment = None
            self.locale = None
            self.blob_storage_reader_handle = None
            self.log_channel_name = None
            self.__log_channel = None

        @classmethod
        async def start_issuing(
                cls, agent_name: str, pass_phrase: str, to: str, cred_def_id: str, cred_def: dict, values: dict, rev_reg_id: str=None,
                preview: List[ProposedAttrib]=None, translation: List[AttribTranslation]=None,
                comment: str=None, locale: str=None
        ):
            machine_class = IssueCredentialProtocol.IssuerStateMachine
            log_channel_name = 'cred-issuing-log/' + uuid.uuid4().hex

            to_verkey = await WalletAgent.key_for_local_did(
                agent_name, pass_phrase, to
            )
            if not to_verkey:
                raise RuntimeError('Unknown pairwise for DID: %s' % str(to))
            state_machine_id = to_verkey
            await WalletAgent.start_state_machine(
                agent_name=agent_name, machine_class=machine_class, machine_id=state_machine_id,
                status=IssueCredentialStatus.Null,
                to=to, cred_def_id=cred_def_id, rev_reg_id=rev_reg_id, log_channel_name=log_channel_name
            )

            data = dict(
                comment=comment,
                locale=locale,
                values=values,
                cred_def=cred_def,
                preview=[p.to_json() for p in preview] if preview else None,
                translation=[t.to_json() for t in translation] if translation else None
            )
            await WalletAgent.invoke_state_machine(
                agent_name=agent_name,
                id_=state_machine_id,
                content_type=IssueCredentialProtocol.MESSAGE_CONTENT_TYPE,
                data=data
            )
            return log_channel_name

        async def handle(self, content_type, data):
            try:
                if self.status == IssueCredentialStatus.Null:
                    # Store Context
                    comment = data.get('comment', None)
                    locale = data.get('locale', None) or IssueCredentialProtocol.DEF_LOCALE
                    values = data.get('values')
                    cred_def = data.get('cred_def')
                    preview = data.get('preview', None)
                    preview = [ProposedAttrib(**item) for item in preview] if preview else None
                    translation = data.get('translation', None)
                    translation = [AttribTranslation(**item) for item in translation] if translation else None
                    self.values_buffer = json.dumps(values)
                    # Call Indy
                    offer = await self.get_wallet().issuer_create_credential_offer(self.cred_def_id)
                    self.cred_offer_buffer = json.dumps(offer)
                    await self.__log(event='Build offer with Indy lib', details=offer)
                    payload = dict(**offer, **cred_def)
                    # Build Aries message
                    id_suffix = uuid.uuid4().hex
                    data = {
                        "@type": IssueCredentialProtocol.OFFER_CREDENTIAL,
                        '~l10n': {"locale": locale},
                        "offers~attach": [
                            {
                                "@id": 'libindy-cred-offer-' + id_suffix,
                                "mime-type": "application/json",
                                "data": {
                                    "base64": base64.b64encode(json.dumps(payload).encode()).decode()
                                }
                            }
                        ]
                    }
                    if comment:
                        data['comment'] = comment
                        data['~l10n'] = {"locale": locale}
                        self.comment = comment
                        self.locale = locale
                    if preview:
                        data["credential_preview"] = {
                            "@type": IssueCredentialProtocol.CREDENTIAL_PREVIEW_TYPE,
                            "attributes": [attrib.to_json() for attrib in preview]
                        }
                    if translation:
                        data['~attach'] = [
                            {
                                "@type": IssueCredentialProtocol.CREDENTIAL_TRANSLATION_TYPE,
                                "id": IssueCredentialProtocol.CREDENTIAL_TRANSLATION_ID,
                                '~l10n': {"locale": locale},
                                "mime-type": "application/json",
                                "data": {
                                    "json": [trans.to_json() for trans in translation]
                                }
                            }
                        ]
                    message_offer = Message(data)
                    await IssueCredentialProtocol.send_message_to_agent(self.to, message_offer, self.get_wallet())
                    self.status = IssueCredentialStatus.OfferCredential
                    await self.__log(event='Send Offer message', details=data)
                else:
                    if content_type in WIRED_CONTENT_TYPES:
                        msg, context = await IssueCredentialProtocol.unpack_agent_message(data, self.get_wallet())
                        success, err_msg = await IssueCredentialProtocol.validate_common_message_blocks(
                            msg,
                            IssueCredentialProtocol.REQUEST_NOT_ACCEPTED,
                            context
                        )
                        if not success:
                            if err_msg:
                                await IssueCredentialProtocol.send_message_to_agent(context.their_did, err_msg, self.get_wallet())

                        if msg.type == IssueCredentialProtocol.REQUEST_CREDENTIAL:
                            if self.status == IssueCredentialStatus.OfferCredential:
                                await self.__log('Received credential request', msg.to_dict())
                                # Issue credential
                                cred_offer = json.loads(self.cred_offer_buffer)
                                cred_request = msg.to_dict().get('requests~attach', None)
                                cred_values = json.loads(self.values_buffer)
                                encoded_cred_values = dict()
                                for key, value in cred_values.items():
                                    encoded_cred_values[key] = dict(raw=str(value), encoded=core.codec.encode(value))
                                if cred_request:
                                    if isinstance(cred_request, list):
                                        cred_request = cred_request[0]

                                    cred_request_body = cred_request.get('data').get('base64')
                                    cred_request_body = base64.b64decode(cred_request_body)
                                    cred_request_body = json.loads(cred_request_body.decode())

                                    ret = await self.get_wallet().issuer_create_credential(
                                        cred_offer=cred_offer,
                                        cred_req=cred_request_body,
                                        cred_values=encoded_cred_values,
                                        rev_reg_id=self.rev_reg_id,
                                        blob_storage_reader_handle=self.blob_storage_reader_handle
                                    )
                                    cred, cred_revoc_id, revoc_reg_delta = ret

                                    await self.__log(
                                        'Issue Credentials atrifacts',
                                        dict(cred=cred, cred_revoc_id=cred_revoc_id, revoc_reg_delta=revoc_reg_delta)
                                    )

                                    issue_suffix = uuid.uuid4().hex
                                    message_id = 'libindy-cred-' + issue_suffix
                                    data = {
                                        "@type": IssueCredentialProtocol.ISSUE_CREDENTIAL,
                                        "~please_ack": {"message_id": message_id},
                                        "credentials~attach": [
                                            {
                                                "@id": message_id,
                                                "mime-type": "application/json",
                                                "~thread": {Message.THREAD_ID: msg.id, Message.SENDER_ORDER: 0},
                                                "data": {
                                                    "base64": base64.b64encode(json.dumps(cred).encode()).decode()
                                                }
                                            }
                                        ]
                                    }
                                    self.ack_message_id = message_id
                                    if self.comment:
                                        data['comment'] = self.commentcomment
                                        data['~l10n'] = {"locale": self.locale}

                                    issue_message = Message(data)
                                    await IssueCredentialProtocol.send_message_to_agent(
                                        self.to, issue_message, self.get_wallet()
                                    )
                                    self.status = IssueCredentialStatus.IssueCredential
                                    await self.__log(event='Issue credential', details=data)

                            else:
                                await self.__send_problem_report(
                                    problem_code=IssueCredentialProtocol.REQUEST_NOT_ACCEPTED,
                                    problem_str='Impossible state machine state',
                                    context=context,
                                    thread_id=msg.id
                                )
                                raise ImpossibleStatus
                        elif msg.type == AckMessage.ACK:
                            if self.status == IssueCredentialStatus.IssueCredential:
                                await self.__log('Received ACK', msg.to_dict())
                                await self.done()
                            else:
                                await self.__send_problem_report(
                                    problem_code=IssueCredentialProtocol.REQUEST_NOT_ACCEPTED,
                                    problem_str='Impossible state machine state',
                                    context=context,
                                    thread_id=msg.id
                                )
                                raise ImpossibleStatus
                        elif msg.type == IssueCredentialProtocol.PROBLEM_REPORT:
                            await self.__log('Received problem report', msg.to_dict())
                            await self.done()
                    else:
                        raise RuntimeError('Unsupported content_type "%s"' % content_type)

            except Exception as e:
                if not isinstance(e, MachineIsDone):
                    logging.exception('Base machine terminated with exception')
                await self.done()

        async def done(self):
            if self.__log_channel is not None:
                await self.__log('Done')
                await self.__log_channel.close()
            await self.__log('Done')
            await super().done()

        async def __send_problem_report(self, problem_code: str, problem_str: str, context: Context, thread_id: str = None):
            err_msg = await IssueCredentialProtocol.send_problem_report(
                self.get_wallet(),
                problem_code,
                problem_str,
                context,
                thread_id
            )
            await self.__log('Send report problem', err_msg.to_dict())

        async def __log(self, event: str, details: dict=None):
            event_message = '%s (%s)' % (event, self.get_id())
            await self.get_wallet().log(message=event_message, details=details)
            if self.__log_channel is None:
                self.__log_channel = await WriteOnlyChannel.create(self.log_channel_name)
            if not self.__log_channel.is_closed:
                await self.__log_channel.write([event_message, details])

    class HolderSateMachine(BaseStateMachine, metaclass=InvokableStateMachineMeta):

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.status = IssueCredentialStatus.Null
            self.to = None
            self.cred_metadata = None
            self.comment = None
            self.cred_def_buffer = None
            self.rev_reg_def = None
            self.cred_def_id = None

        async def handle(self, content_type, data):
            try:
                if content_type in WIRED_CONTENT_TYPES:
                    msg, context = await IssueCredentialProtocol.unpack_agent_message(data, self.get_wallet())
                    self.to = context.their_did
                    success, err_msg = await IssueCredentialProtocol.validate_common_message_blocks(
                        msg,
                        IssueCredentialProtocol.REQUEST_NOT_ACCEPTED,
                        context
                    )
                    if not success:
                        if err_msg:
                            await IssueCredentialProtocol.send_message_to_agent(context.their_did, err_msg, self.get_wallet())
                else:
                    raise RuntimeError('Unsupported content_type "%s"' % content_type)
                if msg.type == IssueCredentialProtocol.OFFER_CREDENTIAL:
                    if self.status == IssueCredentialStatus.Null:
                        await self.__log('Received credential offer', msg.to_dict())
                        offer, offer_body, cred_def_body = await self.__validate_cred_offer(msg, context)
                        self.cred_def_id = offer_body['cred_def_id']

                        link_secret_name = 'salt:' + offer.get('@id', 'default-prover-secret')
                        try:
                            await self.get_wallet().prover_create_master_secret(link_secret_name)
                        except WalletOperationError as e:
                            if 'duplicate' in e.error_message.lower():
                                # nothing to do
                                pass
                            else:
                                raise e
                        # Create Credential request
                        self.cred_def_buffer = json.dumps(cred_def_body)
                        cred_request, metadata = await self.get_wallet().prover_create_credential_req(
                            prover_did=context.my_did,
                            cred_offer=offer_body,
                            cred_def=cred_def_body,
                            master_secret_id=link_secret_name
                        )

                        await self.__log(
                            'Cred request artifacts',
                            dict(cred_request=cred_request, metadata=metadata)
                        )

                        self.cred_metadata = json.dumps(metadata)
                        # Build request
                        data = {
                            "@type": IssueCredentialProtocol.REQUEST_CREDENTIAL,
                            "~thread": {Message.THREAD_ID: msg.id, Message.SENDER_ORDER: 0},
                            "requests~attach": [
                                {
                                    "@id": uuid.uuid4().hex,
                                    "mime-type": "application/json",
                                    "data": {
                                        "base64": base64.b64encode(json.dumps(cred_request).encode()).decode()
                                    }
                                },
                            ]
                        }
                        if self.comment:
                            data['comment'] = self.comment

                        message_request = Message(data)
                        await IssueCredentialProtocol.send_message_to_agent(self.to, message_request, self.get_wallet())
                        await self.__log('Send credential request', message_request.to_dict())
                        self.status = IssueCredentialStatus.RequestCredential
                    else:
                        await self.__send_problem_report(
                            problem_code=IssueCredentialProtocol.OFFER_PROCESSING_ERROR,
                            problem_str='Impossible state machine state',
                            context=context,
                            thread_id=msg.id
                        )
                        raise ImpossibleStatus
                elif msg.type == IssueCredentialProtocol.ISSUE_CREDENTIAL:
                    if self.status == IssueCredentialStatus.RequestCredential:
                        await self.__log('Received Issue credential', msg.to_dict())
                        cred_attach = msg.to_dict().get('credentials~attach', None)
                        if isinstance(cred_attach, list):
                            cred_attach = cred_attach[0]

                        cred_body = cred_attach.get('data').get('base64')
                        cred_body = base64.b64decode(cred_body)
                        cred_body = json.loads(cred_body.decode())
                        cred_def = json.loads(self.cred_def_buffer)

                        # Store credential
                        cred_id = await self.get_wallet().prover_store_credential(
                            cred_req_metadata=json.loads(self.cred_metadata),
                            cred=cred_body,
                            cred_def=cred_def,
                            rev_reg_def=self.rev_reg_def
                        )
                        await self.__log('Store credential with id: %s' % str(cred_id), cred_body)

                        ack_message_id = msg.to_dict().get('~please_ack', {}).get('message_id', None)
                        if ack_message_id:
                            ack = AckMessage.build(ack_message_id)
                            await IssueCredentialProtocol.send_message_to_agent(self.to, ack, self.get_wallet())
                            await self.__log('Send ACK', ack.to_dict())
                        await self.done()
                    else:
                        await self.__send_problem_report(
                            problem_code=IssueCredentialProtocol.ISSUE_PROCESSING_ERROR,
                            problem_str='Impossible state machine state',
                            context=context,
                            thread_id=msg.id
                        )
                        raise ImpossibleStatus
                elif msg.type == IssueCredentialProtocol.PROBLEM_REPORT:
                    await self.__log('Received problem report', msg.to_dict())
                    await self.done()
                else:
                    await self.__send_problem_report(
                        problem_code=IssueCredentialProtocol.RESPONSE_FOR_UNKNOWN_REQUEST,
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

        async def __validate_cred_offer(self, msg: Message, context: Context):
            offer_attaches = msg.to_dict().get('offers~attach', None)
            if isinstance(offer_attaches, dict):
                offer_attaches = [offer_attaches]
            if (not type(offer_attaches) is list) or (type(offer_attaches) is list and len(offer_attaches) == 0):
                await self.__send_problem_report(
                    problem_code=IssueCredentialProtocol.OFFER_PROCESSING_ERROR,
                    problem_str='Expected offer~attach must contains credOffer and credDef',
                    context=context,
                    thread_id=msg.id
                )
                await self.done()

            offer = offer_attaches[0]
            offer_body = None
            cred_def_body = None
            for attach in offer_attaches:
                raw_base64 = attach.get('data', {}).get('base64', None)
                if raw_base64:
                    payload = json.loads(base64.b64decode(raw_base64).decode())
                    offer_fields = ['key_correctness_proof', 'nonce', 'schema_id', 'cred_def_id']
                    cred_def_fields = ['value', 'type', 'ver', 'schemaId', 'id', 'tag']
                    if all([field in payload.keys() for field in offer_fields]):  # check if cred offer content
                        offer_body = {attr: val for attr, val in payload.items() if attr in offer_fields}
                    if all([field in payload.keys() for field in cred_def_fields]):  # check if cred def content
                        cred_def_body = {attr: val for attr, val in payload.items() if attr in cred_def_fields}

            if not offer_body:
                await self.__send_problem_report(
                    problem_code=IssueCredentialProtocol.OFFER_PROCESSING_ERROR,
                    problem_str='Expected offer~attach must contains Payload with offer',
                    context=context,
                    thread_id=msg.id
                )
                await self.done()
            if not cred_def_body:
                await self.__send_problem_report(
                    problem_code=IssueCredentialProtocol.OFFER_PROCESSING_ERROR,
                    problem_str='Expected offer~attach must contains Payload with cred_def data',
                    context=context,
                    thread_id=msg.id
                )
                await self.done()
            return offer, offer_body, cred_def_body

        async def __send_problem_report(self, problem_code: str, problem_str: str, context: Context, thread_id: str=None):
            err_msg = await IssueCredentialProtocol.send_problem_report(
                self.get_wallet(),
                problem_code,
                problem_str,
                context,
                thread_id
            )
            await self.__log('Send report problem', err_msg.to_dict())

        async def __log(self, event: str, details: dict = None):
            event_message = '%s (%s)' % (event, self.get_id())
            await self.get_wallet().log(message=event_message, details=details)
