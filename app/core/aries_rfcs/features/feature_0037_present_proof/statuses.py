from enum import IntEnum


class PresentProofStatus(IntEnum):
    """https://github.com/hyperledger/aries-rfcs/tree/master/features/0037-present-proof"""
    Null = 0

    # --- Verifier ----
    # A Verifier sent request presentation
    RequestSent = 1
    # Verifier received presentation propose
    ProposalReceived = 2
    # Verifier received presentation
    PresentationReceived = 3

    # --- Prover ----
    # Prover sent presentation propose
    ProposalSent = 4
    # Prover sent presentation
    PresentationSent = 5
    # Prover
    RejectSent = 6

    # --- Both ----
    # Actor received request
    RequestReceived = 7
