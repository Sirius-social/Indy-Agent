from enum import IntEnum


class DIDExchangeStatus(IntEnum):
    """https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange"""

    # No exchange exists or is in progress
    Null = 0,

    # The invitation has been shared with the intended invitee(s), and they have not yet sent a exchange_request.
    Invited = 1,

    # A exchange_request has been sent by the invitee to the inviter based on the information in the invitation.
    Requested = 2,

    # A exchange_response has been sent by the inviter to the invitee based on the information in the exchange_request.
    Responded = 3,

    # The exchange has been completed.
    Complete = 4
