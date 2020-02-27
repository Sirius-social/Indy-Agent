import re
import json
import uuid
import time
import struct
import logging
import base64
from collections import UserDict
from typing import List, Dict, Any

import indy.crypto
import core.indy_sdk_utils as indy_sdk_utils
import core.const
from core.base import WireMessageFeature, FeatureMeta, WriteOnlyChannel, EndpointTransport
from core.messages.did_doc import DIDDoc
from core.messages.message import Message
from core.messages.errors import ValidationException as MessageValidationException
from core.serializer.json_serializer import JSONSerializer as Serializer
from core.wallet import WalletAgent, InvokableStateMachineMeta, WalletConnection
from state_machines.base import BaseStateMachine, MachineIsDone
from core.aries_rfcs.features.feature_0095_basic_message.feature import BasicMessage
from core.aries_rfcs.features.feature_0048_trust_ping.feature import TrustPing
from transport.const import WIRED_CONTENT_TYPES


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


class IssueCredentialProtocol(WireMessageFeature, metaclass=FeatureMeta):
    """https://github.com/hyperledger/aries-rfcs/tree/master/features/0036-issue-credential"""

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

    """Problem reports"""
    PROBLEM_REPORT = 'problem_report'
    PROPOSE_NOT_ACCEPTED = "propose_not_accepted"
    OFFER_PROCESSING_ERROR = 'offer_processing_error'
    REQUEST_NOT_ACCEPTED = "request_not_accepted"
    ISSUE_PROCESSING_ERROR = 'issue_processing_error'
    RESPONSE_FOR_UNKNOWN_REQUEST = "response_for_unknown_request"
    """Extended"""

    @classmethod
    async def handle(cls, agent_name: str, wire_message: bytes, my_label: str = None, my_endpoint: str = None) -> bool:
        pass

    WIRED_CONTENT_TYPE = WIRED_CONTENT_TYPES[0]

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

    @classmethod
    async def validate_common_message_blocks(cls, msg: Message, problem_code: str):
        try:
            msg.validate_common_blocks()
            return True, None
        except MessageValidationException as e:
            logging.exception('Validation error while parsing message: %s' % msg.as_json())
            their_did = msg.context.get('from_did')
            if their_did:
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

    @classmethod
    def propose_credential(
            cls,
            comment: str=None, locale: str='en', proposal_attrib: List[ProposedAttrib]=None, schema_id: str=None,
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
                "@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/issue-credential/1.0/credential-preview",
                "attributes": [attrib.to_json() for attrib in proposal_attrib]
            }
            if proposal_attrib_translation:
                data['~attach'] = [
                    {
                        "@type": 'https://github.com/Sirius-social/agent/messages/blob/master/credential-translation',
                        "id": "credential-translation",
                        '~l10n': {"locale": locale},
                        "mime-type": "application/json",
                        "data": {
                            "json": {
                                "type": "AttributesCollection",
                                "translations": [trans.to_json() for trans in proposal_attrib_translation]
                            }
                        }
                    }
                ]
        return Message(data)

    class Issuer:
        pass

    class Holder:
        pass
