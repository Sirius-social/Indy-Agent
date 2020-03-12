import datetime
from typing import Optional

from core import WireMessageFeature
from core.messages.message import Message
from core.messages.did_doc import DIDDoc


class BasicMessage(WireMessageFeature):
    """https://github.com/hyperledger/aries-rfcs/tree/master/features/0095-basic-message"""

    FAMILY_NAME = "basicmessage"
    VERSION = "1.0"
    FAMILY = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/" + FAMILY_NAME + "/" + VERSION + "/"

    MESSAGE = FAMILY + "message"

    @classmethod
    def endorsement(cls, msg: Message) -> bool:
        return False

    async def handle(cls, agent_name: str, wire_message: bytes, my_label: str=None, my_endpoint: str=None):
        return None

    @staticmethod
    def build(content: str) -> Message:
        sent_time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat(' ')
        return Message({
            '@type': BasicMessage.MESSAGE,
            '~l10n': {'locale': 'en'},
            'sent_time': sent_time,
            'content': content
        })

    @staticmethod
    def validate(msg: Message):
        msg.check_for_attrs(
            [
                ('@type', BasicMessage.MESSAGE),
                '~l10n',
                'sent_time',
                'content',
            ]
        )

        Message.check_for_attrs_in_message(
            [
                ('locale', 'en')
            ],
            msg['~l10n']
        )

    @staticmethod
    def extract_verkey_endpoint(msg: Message, key: str) -> (Optional, Optional):
        """
        Extract verkey and endpoint that will be used to send message back to the sender of this message. Might return None.
        """
        vks = msg.get(key, {}).get(DIDDoc.DID_DOC, {}).get('publicKey')
        vk = vks[0].get('publicKeyBase58') if vks and isinstance(vks, list) and len(vks) > 0 else None
        endpoints = msg.get(key, {}).get(DIDDoc.DID_DOC, {}).get('service')
        endpoint = endpoints[0].get('serviceEndpoint') if endpoints and isinstance(endpoints, list) and len(
            endpoints) > 0 else None
        return vk, endpoint

    @staticmethod
    def extract_their_info(msg: Message, key: str):
        """
        Extract the other participant's DID, verkey and endpoint
        :param msg:
        :param key: attribute for extracting
        :return: Return a 4-tuple of (DID, verkey, endpoint, routingKeys)
        """
        their_did = msg[key][DIDDoc.DID]
        did_doc = msg[key][DIDDoc.DID_DOC]
        service = DIDDoc.extract_service(did_doc)
        their_endpoint = service['serviceEndpoint']
        public_keys = msg[key][DIDDoc.DID_DOC]['publicKey']

        def get_key(controller_: str, id_: str):
            for k in public_keys:
                if k['controller'] == controller_ and k["id"] == id_:
                    return k['publicKeyBase58']
            return None

        def extract_key(name: str):
            if "#" in name:
                controller_, id_ = name.split('#')
                return get_key(controller_, id_)
            else:
                return name

        their_vk = extract_key(service["recipientKeys"][0])

        routing_keys = []
        for rk in service.get("routingKeys", []):
            routing_keys.append(extract_key(rk))

        return their_did, their_vk, their_endpoint, routing_keys
