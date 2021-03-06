import json

import indy
from indy.error import IndyError


async def verifier_verify_proof(
        proof_request: dict, proof: dict, schemas: dict, credential_defs: dict,
        rev_reg_defs: dict = None, rev_regs: dict = None
):
    # dict -to -json
    proof_request_json = json.dumps(proof_request)
    proof_json = json.dumps(proof)
    schemas_json = json.dumps(schemas)
    credential_defs_json = json.dumps(credential_defs)
    rev_reg_defs_json = json.dumps(rev_reg_defs or {})
    rev_regs_json = json.dumps(rev_regs or {})
    try:
        success = await indy.anoncreds.verifier_verify_proof(
            proof_request_json=proof_request_json,
            proof_json=proof_json,
            schemas_json=schemas_json,
            credential_defs_json=credential_defs_json,
            rev_reg_defs_json=rev_reg_defs_json,
            rev_regs_json=rev_regs_json
        )
    except IndyError as e:
        error_code = e.error_code
        error_message = e.message
        # backtrace = e.indy_backtrace
        # error_message_full = json.dumps(dict(error_code=str(error_code), error_message=error_message))
        return False, error_message
    else:
        return success, None
