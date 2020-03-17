import json
from typing import Tuple

from indy.crypto import anon_crypt

from core.messages.message import Message
from core.wallet import WalletConnection
from core.serializer.json_serializer import JSONSerializer as Serializer


class RoutingMessage:
    """https://github.com/hyperledger/aries-rfcs/tree/master/concepts/0094-cross-domain-messaging"""

    FAMILY_NAME = "routing"
    VERSION = "1.0"
    FAMILY = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/" + FAMILY_NAME + "/" + VERSION + "/"
    FORWARD = FAMILY + "forward"
    ENC = 'utf-8'

    @staticmethod
    async def pack(msg: Message, wallet: WalletConnection, their_ver_key, routing_keys: list, my_ver_key=None) -> bytes:
        if not routing_keys:
            raise RuntimeError('routing_keys must not be empty')
        payload = await wallet.pack_message(
            Serializer.serialize(msg).decode(RoutingMessage.ENC),
            their_ver_key,
            my_ver_key
        )
        keys_map = {}
        for n in range(len(routing_keys)-1, 0, -1):  # example: IF routing_keys = ['k1', 'k2', 'k3'] THEN n = [2,1]
            outer_key = routing_keys[n]
            inner_key = routing_keys[n-1]
            keys_map[outer_key] = inner_key
        keys_map[routing_keys[0]] = their_ver_key

        for outer_key in routing_keys:
            inner_key = keys_map[outer_key]
            forwarded = Message({
                '@type': RoutingMessage.FORWARD,
                'to': inner_key,
                'msg': json.loads(payload.decode(RoutingMessage.ENC))
            })
            payload = await wallet.pack_message(
                Serializer.serialize(forwarded).decode(RoutingMessage.ENC),
                outer_key,
            )
        return payload

    @staticmethod
    async def unpack(forwarded: Message, wallet: WalletConnection) -> (Message, str, str):
        RoutingMessage.validate(forwarded)
        forwarded_wired = json.dumps(forwarded['msg']).encode(RoutingMessage.ENC)
        unpacked = await wallet.unpack_message(forwarded_wired)
        kwargs = json.loads(unpacked['message'])
        forwarder = Message(**kwargs)
        sender_verkey = unpacked.get('sender_verkey', None)
        recipient_verkey = unpacked.get('recipient_verkey', None)
        return forwarder, recipient_verkey, sender_verkey

    @staticmethod
    def validate(msg: Message):
        msg.check_for_attrs(
            [
                ('@type', RoutingMessage.FORWARD),
                'to',
                'msg',
            ]
        )
