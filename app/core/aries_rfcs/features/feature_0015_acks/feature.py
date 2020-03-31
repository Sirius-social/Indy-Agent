from core import WireMessageFeature
from core.messages.message import Message


class AckMessage:
    """https://github.com/hyperledger/aries-rfcs/tree/master/features/0015-acks"""

    FAMILY_NAME = "notification"
    VERSION = "1.0"
    FAMILY = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/" + FAMILY_NAME + "/" + VERSION + "/"

    ACK = FAMILY + "ack"

    @staticmethod
    def build(thread_id: str, status: str="OK", sender_order: int=0) -> Message:
        return Message({
            '@type': AckMessage.ACK,
            'status': status,
            '~thread': {
                Message.THREAD_ID: thread_id,
                Message.SENDER_ORDER: sender_order
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

    @staticmethod
    def extract_please_ack(msg: Message):
        if '~please_ack' in msg:
            return msg['~please_ack']
        else:
            return None
