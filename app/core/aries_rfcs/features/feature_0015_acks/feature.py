from core import WireMessageFeature
from core.messages.message import Message


class AckMessage:
    """https://github.com/hyperledger/aries-rfcs/tree/master/features/0015-acks"""

    FAMILY_NAME = "notification"
    VERSION = "1.0"
    FAMILY = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/" + FAMILY_NAME + "/" + VERSION + "/"

    ACK = FAMILY + "ack"

    @staticmethod
    def build(thread_id: str, status: str="OK") -> Message:
        return Message({
            '@type': AckMessage.ACK,
            'status': status,
            '~thread': {
                'thid': thread_id
            }
        })

    @staticmethod
    def validate(msg: Message):
        msg.check_for_attrs(
            [
                ('@type', AckMessage.ACK),
                'status',
                '~thread',
            ]
        )
