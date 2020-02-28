from enum import IntEnum


class IssueCredentialStatus(IntEnum):
    """https://github.com/hyperledger/aries-rfcs/tree/master/features/0036-issue-credential"""

    Null = 0

    # A message sent by the Issuer to the potential Holder, describing the credential they intend to offer
    # and possibly the price they expect to be paid.
    OfferCredential = 1

    # This is a message sent by the potential Holder to the Issuer, to request the issuance of a credential.
    RequestCredential = 2

    # This message contains as attached payload the credentials being issued and is sent in response
    # to a valid Request Credential message.
    IssueCredential = 3
