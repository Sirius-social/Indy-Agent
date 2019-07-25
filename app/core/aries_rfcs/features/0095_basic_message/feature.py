import datetime

from core import MessageFeature
from core.messages.message import Message


class BasicMessage(MessageFeature):
    """https://github.com/hyperledger/aries-rfcs/tree/master/features/0095-basic-message"""

    FAMILY_NAME = "basicmessage"
    VERSION = "1.0"
    FAMILY = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/" + FAMILY_NAME + "/" + VERSION + "/"

    MESSAGE = FAMILY + "message"

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

    def endorsement(cls, msg: Message) -> bool:
        return False

    def handle(self, msg: Message):
        return None
