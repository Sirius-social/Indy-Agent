import json

import indy


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
    success = await indy.anoncreds.verifier_verify_proof(
        proof_request_json=proof_request_json,
        proof_json=proof_json,
        schemas_json=schemas_json,
        credential_defs_json=credential_defs_json,
        rev_reg_defs_json=rev_reg_defs_json,
        rev_regs_json=rev_regs_json
    )
    return success
