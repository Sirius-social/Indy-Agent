import json

import indy

from core.pool import get_pool_handle


async def get_schema(did, schema_id):
    pool_handle = await get_pool_handle()
    get_schema_request = await indy.ledger.build_get_schema_request(did, schema_id)
    get_schema_response = await indy.ledger.submit_request(pool_handle, get_schema_request)
    schema_id, resp_json = await indy.ledger.parse_get_schema_response(get_schema_response)
    return schema_id, json.loads(resp_json)


async def get_cred_def(did, cred_def_id):
    pool_handle = await get_pool_handle()
    get_cred_def_request = await indy.ledger.build_get_cred_def_request(did, cred_def_id)
    get_cred_def_response = await indy.ledger.submit_request(pool_handle, get_cred_def_request)
    cred_def_id, resp_json = await indy.ledger.parse_get_cred_def_response(get_cred_def_response)
    return cred_def_id, json.loads(resp_json)


async def prover_get_entities_from_ledger(did, identifiers):
    schemas = {}
    cred_defs = {}
    rev_states = {}
    for item in identifiers.values():
        received_schema_id, received_schema = await get_schema(did, item['schema_id'])
        schemas[received_schema_id] = received_schema

        received_cred_def_id, received_cred_def = await get_cred_def(did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = received_cred_def

        if 'rev_reg_seq_no' in item:
            pass  # TODO Create Revocation States

    return schemas, cred_defs, rev_states


async def verifier_get_entities_from_ledger(did, identifiers):
    schemas = {}
    cred_defs = {}
    rev_reg_defs = {}
    rev_regs = {}
    for item in identifiers:
        received_schema_id, received_schema = await get_schema(did, item['schema_id'])
        schemas[received_schema_id] = received_schema
        received_cred_def_id, received_cred_def = await get_cred_def(did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = received_cred_def

        if 'rev_reg_seq_no' in item:
            pass  # TODO Get Revocation Definitions and Revocation Registries

    return schemas, cred_defs, rev_reg_defs, rev_regs