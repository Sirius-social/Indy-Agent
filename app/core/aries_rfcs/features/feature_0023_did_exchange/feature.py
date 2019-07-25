import base64

from core.base import MessageFeature, FeatureMeta
from core.messages.message import Message
from core.serializer.json_serializer import JSONSerializer as Serializer
from core.wallet import WalletAgent


class DIDExchange(MessageFeature, metaclass=FeatureMeta):
    """https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange"""

    FAMILY_NAME = "didexchange"
    VERSION = "1.0"
    FAMILY = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/" + FAMILY_NAME + "/" + VERSION

    INVITE = FAMILY + "/invitation"
    REQUEST = FAMILY + "/request"
    RESPONSE = FAMILY + "/response"

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
