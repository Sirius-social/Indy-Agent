r"""https://github.com/hyperledger/indy-sdk/tree/master/docs/how-tos
"""
import time
import json
import pprint

import pytest
from pathlib import Path
from indy import blob_storage
from indy import pool, ledger, wallet, did, anoncreds
from indy.error import IndyError, ErrorCode


GENESIS_FILE_PATH = '/home/indy/sandbox/pool_transactions_genesis'
PROTOCOL_VERSION = 2
TEST_POOL_NAME = 'pool'


def path_home() -> Path:
    return Path.home().joinpath(".indy_client")


def print_log(value_color="", value_noncolor=""):
    """set the colors for text."""
    HEADER = '\033[92m'
    ENDC = '\033[0m'
    print(HEADER + value_color + ENDC + str(value_noncolor))


async def open_pool():
    await pool.set_protocol_version(PROTOCOL_VERSION)
    pool_config = json.dumps({'genesis_txn': GENESIS_FILE_PATH})
    try:
        await pool.create_pool_ledger_config(config_name=TEST_POOL_NAME, config=pool_config)
    except IndyError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass
    print_log('\n1. Open pool ledger and get handle from libindy\n')
    pool_handle = await pool.open_pool_ledger(config_name=TEST_POOL_NAME, config=None)
    return pool_handle


async def close_pool(pool_handle):
    await pool.close_pool_ledger(pool_handle)
    await pool.delete_pool_ledger_config(TEST_POOL_NAME)


@pytest.mark.asyncio
async def test_write_nym_and_query_verkey():
    # 1
    pool_handle = await open_pool()
    try:
        # 2
        wallet_config = json.dumps({"id": "wallet"})
        wallet_credentials = json.dumps({"key": "wallet_key"})
        print_log('\n2. Creating new secure wallet\n')
        try:
            await wallet.create_wallet(wallet_config, wallet_credentials)
        except IndyError as ex:
            if ex.error_code == ErrorCode.WalletAlreadyExistsError:
                pass
        # 3
        print_log('\n3. Open wallet and get handle from libindy\n')
        wallet_handle = await wallet.open_wallet(wallet_config, wallet_credentials)

        try:
            # 4
            print_log('\n4. Generating and storing steward DID and verkey\n')
            steward_seed = '000000000000000000000000Steward1'
            did_json = json.dumps({'seed': steward_seed})
            steward_did, steward_verkey = await did.create_and_store_my_did(wallet_handle, did_json)
            print_log('Steward DID: ', steward_did)
            print_log('Steward Verkey: ', steward_verkey)

            # 5
            print_log('\n5. Generating and storing trust anchor DID and verkey\n')
            trust_anchor_did, trust_anchor_verkey = await did.create_and_store_my_did(wallet_handle, "{}")
            print_log('Trust anchor DID: ', trust_anchor_did)
            print_log('Trust anchor Verkey: ', trust_anchor_verkey)

            # 6
            print_log('\n6. Building NYM request to add Trust Anchor to the ledger\n')
            nym_transaction_request = await ledger.build_nym_request(submitter_did=steward_did,
                                                                     target_did=trust_anchor_did,
                                                                     ver_key=trust_anchor_verkey,
                                                                     alias=None,
                                                                     role='TRUST_ANCHOR')
            print_log('NYM transaction request: ')
            pprint.pprint(json.loads(nym_transaction_request))

            # 7.
            print_log('\n7. Sending NYM request to the ledger\n')
            nym_transaction_response = await ledger.sign_and_submit_request(pool_handle=pool_handle,
                                                                            wallet_handle=wallet_handle,
                                                                            submitter_did=steward_did,
                                                                            request_json=nym_transaction_request)
            print_log('NYM transaction response: ')
            pprint.pprint(json.loads(nym_transaction_response))

            # 8
            print_log('\n8. Generating and storing DID and verkey representing a Client '
                      'that wants to obtain Trust Anchor Verkey\n')
            client_did, client_verkey = await did.create_and_store_my_did(wallet_handle, "{}")
            print_log('Client DID: ', client_did)
            print_log('Client Verkey: ', client_verkey)

            # 9
            print_log('\n9. Building the GET_NYM request to query trust anchor verkey\n')
            get_nym_request = await ledger.build_get_nym_request(submitter_did=client_did,
                                                                 target_did=trust_anchor_did)
            print_log('GET_NYM request: ')
            pprint.pprint(json.loads(get_nym_request))

            # 10
            print_log('\n10. Sending the Get NYM request to the ledger\n')
            get_nym_response_json = await ledger.submit_request(pool_handle=pool_handle,
                                                                request_json=get_nym_request)
            get_nym_response = json.loads(get_nym_response_json)
            print_log('GET_NYM response: ')
            pprint.pprint(get_nym_response)

            # 11
            print_log('\n11. Comparing Trust Anchor verkey as written by Steward and as retrieved in GET_NYM '
                      'response submitted by Client\n')
            print_log('Written by Steward: ', trust_anchor_verkey)
            verkey_from_ledger = json.loads(get_nym_response['result']['data'])['verkey']
            print_log('Queried from ledger: ', verkey_from_ledger)
            assert verkey_from_ledger == trust_anchor_verkey
        finally:
            print_log('\nClosing wallet\n')
            await wallet.close_wallet(wallet_handle)
            await wallet.delete_wallet(wallet_config, wallet_credentials)
    finally:
        await close_pool(pool_handle)
    pass


@pytest.mark.asyncio
async def test_rotate_key():
    # 1
    pool_handle = await open_pool()
    try:
        wallet_config = json.dumps({"id": "wallet"})
        wallet_credentials = json.dumps({"key": "wallet_key"})
        print_log('\n2. Creating new secure wallet\n')
        try:
            await wallet.create_wallet(wallet_config, wallet_credentials)
        except IndyError as ex:
            if ex.error_code == ErrorCode.WalletAlreadyExistsError:
                pass
        # 2
        print_log('\n2. Open wallet and get handle from libindy\n')
        wallet_handle = await wallet.open_wallet(wallet_config, wallet_credentials)

        try:

            # 5.
            print_log('\n5. Generating and storing steward DID and verkey\n')
            steward_seed = '000000000000000000000000Steward1'
            did_json = json.dumps({'seed': steward_seed})
            steward_did, steward_verkey = await did.create_and_store_my_did(wallet_handle, did_json)
            print_log('Steward DID: ', steward_did)
            print_log('Steward Verkey: ', steward_verkey)

            # 6.
            print_log('\n6. Generating and storing trust anchor DID and verkey\n')
            trust_anchor_did, trust_anchor_verkey = await did.create_and_store_my_did(wallet_handle, "{}")
            print_log('Trust Anchor DID: ', trust_anchor_did)
            print_log('Trust Anchor Verkey: ', trust_anchor_verkey)

            # 7.
            print_log('\n7. Building NYM request to add Trust Anchor to the ledger\n')
            nym_transaction_request = await ledger.build_nym_request(submitter_did=steward_did,
                                                                     target_did=trust_anchor_did,
                                                                     ver_key=trust_anchor_verkey,
                                                                     alias=None,
                                                                     role='TRUST_ANCHOR')
            print_log('NYM request: ')
            pprint.pprint(json.loads(nym_transaction_request))

            # 8.
            print_log('\n8. Sending NYM request to the ledger\n')
            nym_transaction_response = await ledger.sign_and_submit_request(pool_handle=pool_handle,
                                                                            wallet_handle=wallet_handle,
                                                                            submitter_did=steward_did,
                                                                            request_json=nym_transaction_request)
            print_log('NYM response: ')
            pprint.pprint(json.loads(nym_transaction_response))

            # 9.
            print_log('\n9. Generating new verkey of trust anchor in wallet\n')
            new_verkey = await did.replace_keys_start(wallet_handle, trust_anchor_did, "{}")
            print_log('New Trust Anchor Verkey: ', new_verkey)

            # 10.
            print_log('\n10. Building NYM request to update new verkey to ledger\n')
            nym_request = await ledger.build_nym_request(trust_anchor_did, trust_anchor_did, new_verkey, None, 'TRUST_ANCHOR')
            print_log('NYM request:')
            pprint.pprint(json.loads(nym_request))

            # 11.
            print_log('\n11. Sending NYM request to the ledger\n')
            nym_response = await ledger.sign_and_submit_request(pool_handle, wallet_handle, trust_anchor_did, nym_request)
            print_log('NYM response:')
            pprint.pprint(json.loads(nym_response))

            # 12.
            print_log('\n12. Apply new verkey in wallet\n')
            await did.replace_keys_apply(wallet_handle, trust_anchor_did)

            # 13.
            print_log('\n13. Reading new verkey from wallet\n')
            verkey_in_wallet = await did.key_for_local_did(wallet_handle, trust_anchor_did)
            print_log('Trust Anchor Verkey in wallet: ', verkey_in_wallet)

            # 14.
            print_log('\n14. Building GET_NYM request to get Trust Anchor verkey\n')
            get_nym_request = await ledger.build_get_nym_request(trust_anchor_did, trust_anchor_did)
            print_log('Get NYM request:')
            pprint.pprint(json.loads(get_nym_request))

            # 15.
            print_log('\n15. Sending GET_NYM request to ledger\n')
            get_nym_response_json = await ledger.submit_request(pool_handle, get_nym_request)
            get_nym_response = json.loads(get_nym_response_json)
            print_log('GET NYM response:')
            pprint.pprint(get_nym_response)

            # 16.
            print_log('\n16. Comparing Trust Anchor verkeys: written by Steward (original), '
                      'current in wallet and current from ledger\n')
            print_log('Written by Steward: ', trust_anchor_verkey)
            print_log('Current in wallet: ', verkey_in_wallet)
            verkey_from_ledger = json.loads(get_nym_response['result']['data'])['verkey']
            print_log('Current from ledger: ', verkey_from_ledger)
            assert verkey_from_ledger == verkey_in_wallet != trust_anchor_verkey
        finally:
            # 17.
            print_log('\n17. Closing wallet and pool\n')
            await wallet.close_wallet(wallet_handle)

            # 18.
            print_log('\n18. Deleting created wallet\n')
            await wallet.delete_wallet(wallet_config, wallet_credentials)

    finally:
        print_log('\n19. Deleting pool ledger config')
        await close_pool(pool_handle)


@pytest.mark.asyncio
async def test_save_schema_and_cred_def():
    # 1
    pool_handle = await open_pool()
    try:
        wallet_config = json.dumps({"id": "wallet"})
        wallet_credentials = json.dumps({"key": "wallet_key"})
        print_log('\n2. Creating new secure wallet\n')
        try:
            await wallet.create_wallet(wallet_config, wallet_credentials)
        except IndyError as ex:
            if ex.error_code == ErrorCode.WalletAlreadyExistsError:
                pass
        # 2
        print_log('\n2. Open wallet and get handle from libindy\n')
        wallet_handle = await wallet.open_wallet(wallet_config, wallet_credentials)

        try:
            # 5.
            print_log('\n5. Generating and storing steward DID and verkey\n')
            steward_seed = '000000000000000000000000Steward1'
            did_json = json.dumps({'seed': steward_seed})
            steward_did, steward_verkey = await did.create_and_store_my_did(wallet_handle, did_json)
            print_log('Steward DID: ', steward_did)
            print_log('Steward Verkey: ', steward_verkey)

            # 6.
            print_log('\n6. Generating and storing trust anchor DID and verkey\n')
            trust_anchor_did, trust_anchor_verkey = await did.create_and_store_my_did(wallet_handle, "{}")
            print_log('Trust anchor DID: ', trust_anchor_did)
            print_log('Trust anchor Verkey: ', trust_anchor_verkey)

            # 7.
            print_log('\n7. Building NYM request to add Trust Anchor to the ledger\n')
            nym_transaction_request = await ledger.build_nym_request(submitter_did=steward_did,
                                                                     target_did=trust_anchor_did,
                                                                     ver_key=trust_anchor_verkey,
                                                                     alias=None,
                                                                     role='TRUST_ANCHOR')
            print_log('NYM transaction request: ')
            pprint.pprint(json.loads(nym_transaction_request))

            # 8.
            print_log('\n8. Sending NYM request to the ledger\n')
            nym_transaction_response = await ledger.sign_and_submit_request(pool_handle=pool_handle,
                                                                            wallet_handle=wallet_handle,
                                                                            submitter_did=steward_did,
                                                                            request_json=nym_transaction_request)
            print_log('NYM transaction response: ')
            pprint.pprint(json.loads(nym_transaction_response))

            # 9.
            print_log('\n9. Issuer create Credential Schema\n')
            schema = {
                'name': 'gvt',
                'version': '1.0',
                'attributes': '["age", "sex", "height", "name"]'
            }
            issuer_schema_id, issuer_schema_json = await anoncreds.issuer_create_schema(steward_did,
                                                                                        schema['name'],
                                                                                        schema['version'],
                                                                                        schema['attributes'])
            print_log('Schema: ')
            pprint.pprint(issuer_schema_json)

            # 10.
            print_log('\n10. Build the SCHEMA request to add new schema to the ledger\n')
            schema_request = await ledger.build_schema_request(steward_did, issuer_schema_json)
            print_log('Schema request: ')
            pprint.pprint(json.loads(schema_request))

            # 11.
            print_log('\n11. Sending the SCHEMA request to the ledger\n')
            schema_response = \
                await ledger.sign_and_submit_request(pool_handle,
                                                     wallet_handle,
                                                     steward_did,
                                                     schema_request)
            print_log('Schema response:')
            pprint.pprint(json.loads(schema_response))

            # 12.
            print_log('\n12. Creating and storing Credential Definition using anoncreds as Trust Anchor, for the given Schema\n')
            cred_def_tag = 'TAG1'
            cred_def_type = 'CL'
            cred_def_config = json.dumps({"support_revocation": False})

            (cred_def_id, cred_def_json) = \
                await anoncreds.issuer_create_and_store_credential_def(wallet_handle,
                                                                       trust_anchor_did,
                                                                       issuer_schema_json,
                                                                       cred_def_tag,
                                                                       cred_def_type,
                                                                       cred_def_config)
            print_log('Credential definition: ')
            pprint.pprint(json.loads(cred_def_json))
        finally:
            # 17.
            print_log('\n17. Closing wallet and pool\n')
            await wallet.close_wallet(wallet_handle)

            # 18.
            print_log('\n18. Deleting created wallet\n')
            await wallet.delete_wallet(wallet_config, wallet_credentials)

    finally:
        print_log('\n19. Deleting pool ledger config')
        await close_pool(pool_handle)


@pytest.mark.asyncio
async def test_issue_credential():
    # 1
    pool_handle = await open_pool()
    try:
        issuer_wallet_config = json.dumps({"id": "issuer_wallet"})
        issuer_wallet_credentials = json.dumps({"key": "issuer_wallet_key"})
        print_log('\n3. Creating Issuer wallet and opening it to get the handle.\n')
        await wallet.create_wallet(issuer_wallet_config, issuer_wallet_credentials)
        issuer_wallet_handle = await wallet.open_wallet(issuer_wallet_config, issuer_wallet_credentials)

        try:
            # 4.
            print_log('\n4. Generating and storing steward DID and verkey\n')
            steward_seed = '000000000000000000000000Steward1'
            did_json = json.dumps({'seed': steward_seed})
            steward_did, steward_verkey = await did.create_and_store_my_did(issuer_wallet_handle, did_json)
            print_log('Steward DID: ', steward_did)
            print_log('Steward Verkey: ', steward_verkey)

            # 5.
            print_log('\n5. Generating and storing trust anchor DID and verkey\n')
            trust_anchor_did, trust_anchor_verkey = await did.create_and_store_my_did(issuer_wallet_handle, "{}")
            print_log('Trust anchor DID: ', trust_anchor_did)
            print_log('Trust anchor Verkey: ', trust_anchor_verkey)

            # 6.
            print_log('\n6. Building NYM request to add Trust Anchor to the ledger\n')
            nym_transaction_request = await ledger.build_nym_request(submitter_did=steward_did,
                                                                     target_did=trust_anchor_did,
                                                                     ver_key=trust_anchor_verkey,
                                                                     alias=None,
                                                                     role='TRUST_ANCHOR')
            print_log('NYM transaction request: ')
            pprint.pprint(json.loads(nym_transaction_request))

            # 7.
            print_log('\n7. Sending NYM request to the ledger\n')
            nym_transaction_response = await ledger.sign_and_submit_request(pool_handle=pool_handle,
                                                                            wallet_handle=issuer_wallet_handle,
                                                                            submitter_did=steward_did,
                                                                            request_json=nym_transaction_request)
            print_log('NYM transaction response: ')
            pprint.pprint(json.loads(nym_transaction_response))

            # 8.
            print_log('\n8. Issuer create Credential Schema\n')
            schema = {
                'name': 'gvt',
                'version': '1.0',
                'attributes': '["age", "sex", "height", "name"]'
            }
            issuer_schema_id, issuer_schema_json = await anoncreds.issuer_create_schema(steward_did,
                                                                                        schema['name'],
                                                                                        schema['version'],
                                                                                        schema['attributes'])
            print_log('Schema: ')
            pprint.pprint(issuer_schema_json)

            # 9.
            print_log('\n9. Build the SCHEMA request to add new schema to the ledger\n')
            schema_request = await ledger.build_schema_request(steward_did, issuer_schema_json)
            print_log('Schema request: ')
            pprint.pprint(json.loads(schema_request))

            # 10.
            print_log('\n10. Sending the SCHEMA request to the ledger\n')
            schema_response = \
                await ledger.sign_and_submit_request(pool_handle,
                                                     issuer_wallet_handle,
                                                     steward_did,
                                                     schema_request)
            print_log('Schema response:')
            pprint.pprint(json.loads(schema_response))

            # 11.
            print_log(
                '\n11. Creating and storing Credential Definition using anoncreds as Trust Anchor, for the given Schema\n')
            cred_def_tag = 'TAG1'
            cred_def_type = 'CL'
            cred_def_config = json.dumps({"support_revocation": False})

            (cred_def_id, cred_def_json) = \
                await anoncreds.issuer_create_and_store_credential_def(issuer_wallet_handle,
                                                                       trust_anchor_did,
                                                                       issuer_schema_json,
                                                                       cred_def_tag,
                                                                       cred_def_type,
                                                                       cred_def_config)
            print_log('Credential definition: ')
            pprint.pprint(json.loads(cred_def_json))

            # 12.
            print_log('\n12. Creating Prover wallet and opening it to get the handle.\n')
            prover_did = 'VsKV7grR1BUE29mG2Fm2kX'
            prover_wallet_config = json.dumps({"id": "prover_wallet"})
            prover_wallet_credentials = json.dumps({"key": "prover_wallet_key"})
            await wallet.create_wallet(prover_wallet_config, prover_wallet_credentials)
            prover_wallet_handle = await wallet.open_wallet(prover_wallet_config, prover_wallet_credentials)

            try:
                # 13.
                print_log('\n13. Prover is creating Link Secret\n')
                prover_link_secret_name = 'link_secret'
                link_secret_id = await anoncreds.prover_create_master_secret(prover_wallet_handle,
                                                                             prover_link_secret_name)

                # 14.
                print_log('\n14. Issuer (Trust Anchor) is creating a Credential Offer for Prover\n')
                cred_offer_json = await anoncreds.issuer_create_credential_offer(issuer_wallet_handle,
                                                                                 cred_def_id)
                print_log('Credential Offer: ')
                pprint.pprint(json.loads(cred_offer_json))

                # 15.
                print_log('\n15. Prover creates Credential Request for the given credential offer\n')
                (cred_req_json, cred_req_metadata_json) = \
                    await anoncreds.prover_create_credential_req(prover_wallet_handle,
                                                                 prover_did,
                                                                 cred_offer_json,
                                                                 cred_def_json,
                                                                 prover_link_secret_name)
                print_log('Credential Request: ')
                pprint.pprint(json.loads(cred_req_json))

                # 16.
                print_log('\n16. Issuer (Trust Anchor) creates Credential for Credential Request\n')
                cred_values_json = json.dumps({
                    "sex": {"raw": "male",
                            "encoded": "5944657099558967239210949258394887428692050081607692519917050011144233"},
                    "name": {"raw": "Alex", "encoded": "1139481716457488690172217916278103335"},
                    "height": {"raw": "175", "encoded": "175"},
                    "age": {"raw": "28", "encoded": "28"}
                })
                (cred_json, _, _) = \
                    await anoncreds.issuer_create_credential(issuer_wallet_handle,
                                                             cred_offer_json,
                                                             cred_req_json,
                                                             cred_values_json, None, None)
                print_log('Credential: ')
                pprint.pprint(json.loads(cred_json))

                # 17.
                print_log('\n17. Prover processes and stores received Credential\n')
                await anoncreds.prover_store_credential(prover_wallet_handle, None,
                                                        cred_req_metadata_json,
                                                        cred_json,
                                                        cred_def_json, None)
            finally:
                print_log('\n18. Closing prover wallet\n')
                await wallet.close_wallet(prover_wallet_handle)
                # 18.
                print_log('\n19. Deleting prover created wallet\n')
                await wallet.delete_wallet(prover_wallet_config, prover_wallet_credentials)

        finally:
            # 17.
            print_log('\n20. Closing issuer wallet\n')
            await wallet.close_wallet(issuer_wallet_handle)
            # 18.
            print_log('\n21. Deleting issuer created wallet\n')
            await wallet.delete_wallet(issuer_wallet_config, issuer_wallet_credentials)
    finally:
        print_log('\n22. Deleting pool ledger config')
        await close_pool(pool_handle)


@pytest.mark.asyncio
async def test_negotiate_proof():
    # 1
    pool_handle = await open_pool()
    try:
        issuer_wallet_config = json.dumps({"id": "issuer_wallet"})
        issuer_wallet_credentials = json.dumps({"key": "issuer_wallet_key"})
        print_log('\n3. Creating Issuer wallet and opening it to get the handle.\n')
        await wallet.create_wallet(issuer_wallet_config, issuer_wallet_credentials)
        issuer_wallet_handle = await wallet.open_wallet(issuer_wallet_config, issuer_wallet_credentials)

        try:
            print_log('\n4. Generating and storing steward DID and verkey\n')
            steward_seed = '000000000000000000000000Steward1'
            did_json = json.dumps({'seed': steward_seed})
            steward_did, steward_verkey = await did.create_and_store_my_did(issuer_wallet_handle, did_json)
            print_log('Steward DID: ', steward_did)
            print_log('Steward Verkey: ', steward_verkey)

            # 5.
            print_log('\n5. Generating and storing trust anchor DID and verkey\n')
            trust_anchor_did, trust_anchor_verkey = await did.create_and_store_my_did(issuer_wallet_handle, "{}")
            print_log('Trust anchor DID: ', trust_anchor_did)
            print_log('Trust anchor Verkey: ', trust_anchor_verkey)

            # 6.
            print_log('\n6. Building NYM request to add Trust Anchor to the ledger\n')
            nym_transaction_request = await ledger.build_nym_request(submitter_did=steward_did,
                                                                     target_did=trust_anchor_did,
                                                                     ver_key=trust_anchor_verkey,
                                                                     alias=None,
                                                                     role='TRUST_ANCHOR')
            print_log('NYM transaction request: ')
            pprint.pprint(json.loads(nym_transaction_request))

            # 7.
            print_log('\n7. Sending NYM request to the ledger\n')
            nym_transaction_response = await ledger.sign_and_submit_request(pool_handle=pool_handle,
                                                                            wallet_handle=issuer_wallet_handle,
                                                                            submitter_did=steward_did,
                                                                            request_json=nym_transaction_request)
            print_log('NYM transaction response: ')
            pprint.pprint(json.loads(nym_transaction_response))

            # 8.
            print_log('\n8. Issuer create Credential Schema\n')
            schema = {
                'name': 'gvt',
                'version': '1.0',
                'attributes': '["age", "sex", "height", "name"]'
            }
            issuer_schema_id, issuer_schema_json = await anoncreds.issuer_create_schema(steward_did,
                                                                                        schema['name'],
                                                                                        schema['version'],
                                                                                        schema['attributes'])
            print_log('Schema: ')
            pprint.pprint(issuer_schema_json)

            # 9.
            print_log('\n9. Build the SCHEMA request to add new schema to the ledger\n')
            schema_request = await ledger.build_schema_request(steward_did, issuer_schema_json)
            print_log('Schema request: ')
            pprint.pprint(json.loads(schema_request))

            # 10.
            print_log('\n10. Sending the SCHEMA request to the ledger\n')
            schema_response = \
                await ledger.sign_and_submit_request(pool_handle,
                                                     issuer_wallet_handle,
                                                     steward_did,
                                                     schema_request)
            print_log('Schema response:')
            pprint.pprint(json.loads(schema_response))

            # 11.
            print_log(
                '\n11. Creating and storing Credential Definition using anoncreds as Trust Anchor, for the given Schema\n')
            cred_def_tag = 'TAG1'
            cred_def_type = 'CL'
            cred_def_config = json.dumps({"support_revocation": False})

            (cred_def_id, cred_def_json) = \
                await anoncreds.issuer_create_and_store_credential_def(issuer_wallet_handle,
                                                                       trust_anchor_did,
                                                                       issuer_schema_json,
                                                                       cred_def_tag,
                                                                       cred_def_type,
                                                                       cred_def_config)
            print_log('Credential definition: ')
            pprint.pprint(json.loads(cred_def_json))
            # 12.
            print_log('\n12. Creating Prover wallet and opening it to get the handle.\n')
            prover_did = 'VsKV7grR1BUE29mG2Fm2kX'
            prover_wallet_config = json.dumps({"id": "prover_wallet"})
            prover_wallet_credentials = json.dumps({"key": "prover_wallet_key"})
            await wallet.create_wallet(prover_wallet_config, prover_wallet_credentials)
            prover_wallet_handle = await wallet.open_wallet(prover_wallet_config, prover_wallet_credentials)

            try:
                # 13.
                print_log('\n13. Prover is creating Link Secret\n')
                prover_link_secret_name = 'link_secret'
                link_secret_id = await anoncreds.prover_create_master_secret(prover_wallet_handle,
                                                                             prover_link_secret_name)

                # 14.
                print_log('\n14. Issuer (Trust Anchor) is creating a Credential Offer for Prover\n')
                cred_offer_json = await anoncreds.issuer_create_credential_offer(issuer_wallet_handle,
                                                                                 cred_def_id)
                print_log('Credential Offer: ')
                pprint.pprint(json.loads(cred_offer_json))

                # 15.
                print_log('\n15. Prover creates Credential Request for the given credential offer\n')
                (cred_req_json, cred_req_metadata_json) = \
                    await anoncreds.prover_create_credential_req(prover_wallet_handle,
                                                                 prover_did,
                                                                 cred_offer_json,
                                                                 cred_def_json,
                                                                 prover_link_secret_name)
                print_log('Credential Request: ')
                pprint.pprint(json.loads(cred_req_json))

                # 16.
                print_log('\n16. Issuer (Trust Anchor) creates Credential for Credential Request\n')
                cred_values_json = json.dumps({
                    "sex": {"raw": "male",
                            "encoded": "5944657099558967239210949258394887428692050081607692519917050011144233"},
                    "name": {"raw": "Alex", "encoded": "1139481716457488690172217916278103335"},
                    "height": {"raw": "175", "encoded": "175"},
                    "age": {"raw": "28", "encoded": "28"}
                })
                (cred_json, _, _) = \
                    await anoncreds.issuer_create_credential(issuer_wallet_handle,
                                                             cred_offer_json,
                                                             cred_req_json,
                                                             cred_values_json, None, None)
                print_log('Credential: ')
                pprint.pprint(json.loads(cred_json))

                # 17.
                print_log('\n17. Prover processes and stores received Credential\n')
                await anoncreds.prover_store_credential(prover_wallet_handle, None,
                                                        cred_req_metadata_json,
                                                        cred_json,
                                                        cred_def_json, None)

                # 18.
                print_log('\n18. Prover gets Credentials for Proof Request\n')
                proof_request = {
                    'nonce': '123432421212',
                    'name': 'proof_req_1',
                    'version': '0.1',
                    'requested_attributes': {
                        'attr1_referent': {
                            'name': 'name',
                            "restrictions": {
                                "issuer_did": trust_anchor_did,
                                "schema_id": issuer_schema_id
                            }
                        }
                    },
                    'requested_predicates': {
                        'predicate1_referent': {
                            'name': 'age',
                            'p_type': '>=',
                            'p_value': 18,
                            "restrictions": {
                                "issuer_did": trust_anchor_did
                            }
                        }
                    }
                }
                print_log('Proof Request: ')
                pprint.pprint(proof_request)

                # 19.
                print_log('\n19. Prover gets Credentials for attr1_referent anf predicate1_referent\n')
                proof_req_json = json.dumps(proof_request)
                prover_cred_search_handle = \
                    await anoncreds.prover_search_credentials_for_proof_req(prover_wallet_handle, proof_req_json, None)

                creds_for_attr1 = await anoncreds.prover_fetch_credentials_for_proof_req(prover_cred_search_handle,
                                                                                         'attr1_referent', 1)
                prover_cred_for_attr1 = json.loads(creds_for_attr1)[0]['cred_info']
                print_log('Prover credential for attr1_referent: ')
                pprint.pprint(prover_cred_for_attr1)

                creds_for_predicate1 = await anoncreds.prover_fetch_credentials_for_proof_req(prover_cred_search_handle,
                                                                                              'predicate1_referent', 1)
                prover_cred_for_predicate1 = json.loads(creds_for_predicate1)[0]['cred_info']
                print_log('Prover credential for predicate1_referent: ')
                pprint.pprint(prover_cred_for_predicate1)

                await anoncreds.prover_close_credentials_search_for_proof_req(prover_cred_search_handle)

                # 20.
                print_log('\n20. Prover creates Proof for Proof Request\n')
                prover_requested_creds = json.dumps({
                    'self_attested_attributes': {},
                    'requested_attributes': {
                        'attr1_referent': {
                            'cred_id': prover_cred_for_attr1['referent'],
                            'revealed': True
                        }
                    },
                    'requested_predicates': {
                        'predicate1_referent': {
                            'cred_id': prover_cred_for_predicate1['referent']
                        }
                    }
                })
                print_log('Requested Credentials for Proving: ')
                pprint.pprint(json.loads(prover_requested_creds))

                prover_schema_id = json.loads(cred_offer_json)['schema_id']
                schemas_json = json.dumps({prover_schema_id: json.loads(issuer_schema_json)})
                cred_defs_json = json.dumps({cred_def_id: json.loads(cred_def_json)})
                proof_json = await anoncreds.prover_create_proof(prover_wallet_handle,
                                                                 proof_req_json,
                                                                 prover_requested_creds,
                                                                 link_secret_id,
                                                                 schemas_json,
                                                                 cred_defs_json,
                                                                 "{}")
                proof = json.loads(proof_json)
                assert 'Alex' == proof['requested_proof']['revealed_attrs']['attr1_referent']["raw"]

                # 21.
                print_log('\n21. Verifier is verifying proof from Prover\n')
                assert await anoncreds.verifier_verify_proof(proof_req_json,
                                                             proof_json,
                                                             schemas_json,
                                                             cred_defs_json,
                                                             "{}", "{}")
            finally:
                print_log('\n18. Closing prover wallet\n')
                await wallet.close_wallet(prover_wallet_handle)
                # 18.
                print_log('\n19. Deleting prover created wallet\n')
                await wallet.delete_wallet(prover_wallet_config, prover_wallet_credentials)

        finally:
            # 17.
            print_log('\n20. Closing issuer wallet\n')
            await wallet.close_wallet(issuer_wallet_handle)
            # 18.
            print_log('\n21. Deleting issuer created wallet\n')
            await wallet.delete_wallet(issuer_wallet_config, issuer_wallet_credentials)
    finally:
        print_log('\n22. Deleting pool ledger config')
        await close_pool(pool_handle)


@pytest.mark.asyncio
async def test_revocation():
    # 1
    pool_handle = await open_pool()
    try:
        issuer = {
            'did': 'NcYxiDXkpYi6ov5FcYDi1e',
            'wallet_config': json.dumps({'id': 'issuer_wallet'}),
            'wallet_credentials': json.dumps({'key': 'issuer_wallet_key'})
        }
        prover = {
            'did': 'VsKV7grR1BUE29mG2Fm2kX',
            'wallet_config': json.dumps({"id": "prover_wallet"}),
            'wallet_credentials': json.dumps({"key": "issuer_wallet_key"})
        }
        verifier = {}
        store = {}

        # Set protocol version 2 to work with Indy Node 1.4
        await pool.set_protocol_version(PROTOCOL_VERSION)

        # 1. Create Issuer Wallet and Get Wallet Handle
        await wallet.create_wallet(issuer['wallet_config'], issuer['wallet_credentials'])
        issuer['wallet'] = await wallet.open_wallet(issuer['wallet_config'], issuer['wallet_credentials'])

        # 2. Create Prover Wallet and Get Wallet Handle
        await wallet.create_wallet(prover['wallet_config'], prover['wallet_credentials'])
        prover['wallet'] = await wallet.open_wallet(prover['wallet_config'], prover['wallet_credentials'])

        # 3. Issuer create Credential Schema
        schema = {
            'name': 'gvt',
            'version': '1.0',
            'attributes': '["age", "sex", "height", "name"]'
        }
        issuer['schema_id'], issuer['schema'] = await anoncreds.issuer_create_schema(issuer['did'], schema['name'],
                                                                                     schema['version'],
                                                                                     schema['attributes'])
        store[issuer['schema_id']] = issuer['schema']

        # 4. Issuer create Credential Definition for Schema
        cred_def = {
            'tag': 'cred_def_tag',
            'type': 'CL',
            'config': json.dumps({"support_revocation": True})
        }
        issuer['cred_def_id'], issuer['cred_def'] = await anoncreds.issuer_create_and_store_credential_def(
            issuer['wallet'], issuer['did'], issuer['schema'], cred_def['tag'], cred_def['type'], cred_def['config'])
        store[issuer['cred_def_id']] = issuer['cred_def']

        # 5. Issuer create Revocation Registry
        issuer['tails_writer_config'] = json.dumps({'base_dir': str(path_home().joinpath("tails")), 'uri_pattern': ''})
        issuer['tails_writer'] = await blob_storage.open_writer('default', issuer['tails_writer_config'])

        revoc_reg_def = {
            'tag': 'cred_def_tag',
            'config': json.dumps({"max_cred_num": 5, 'issuance_type': 'ISSUANCE_ON_DEMAND'})
        }
        (issuer['rev_reg_id'], issuer['rev_reg_def'], issuer['rev_reg_entry']) = \
            await anoncreds.issuer_create_and_store_revoc_reg(issuer['wallet'], issuer['did'], None,
                                                              revoc_reg_def['tag'],
                                                              issuer['cred_def_id'], revoc_reg_def['config'],
                                                              issuer['tails_writer'])
        store[issuer['rev_reg_id']] = {
            'definition': issuer['rev_reg_def'],
            'value': issuer['rev_reg_entry']
        }

        # 6. Prover create Master Secret
        prover['master_secret_id'] = await anoncreds.prover_create_master_secret(prover['wallet'], None)

        # 7. Issuer create Credential Offer
        issuer['cred_offer'] = await anoncreds.issuer_create_credential_offer(issuer['wallet'], issuer['cred_def_id'])
        prover['cred_offer'] = issuer['cred_offer']

        cred_offer = json.loads(prover['cred_offer'])
        prover['cred_def_id'] = cred_offer['cred_def_id']
        prover['schema_id'] = cred_offer['schema_id']

        prover['cred_def'] = store[prover['cred_def_id']]
        prover['schema'] = store[prover['schema_id']]

        # 8. Prover create Credential Request
        prover['cred_req'], prover['cred_req_metadata'] = \
            await anoncreds.prover_create_credential_req(prover['wallet'], prover['did'], prover['cred_offer'],
                                                         prover['cred_def'], prover['master_secret_id'])

        # 9. Issuer open Tails reader
        issuer['blob_storage_reader'] = await blob_storage.open_reader('default', issuer['tails_writer_config'])

        try:
            # 10. Issuer create Credential
            prover['cred_values'] = json.dumps({
                "sex": {"raw": "male",
                        "encoded": "5944657099558967239210949258394887428692050081607692519917050011144233"},
                "name": {"raw": "Alex", "encoded": "1139481716457488690172217916278103335"},
                "height": {"raw": "175", "encoded": "175"},
                "age": {"raw": "28", "encoded": "28"}
            })
            issuer['cred_values'] = prover['cred_values']
            issuer['cred_req'] = prover['cred_req']

            (cred_json, rev_id, rev_reg_delta_json) = \
                await anoncreds.issuer_create_credential(issuer['wallet'], issuer['cred_offer'], issuer['cred_req'],
                                                         issuer['cred_values'], issuer['rev_reg_id'],
                                                         issuer['blob_storage_reader'])
            issuer['rev_id'] = rev_id
            store[issuer['rev_reg_id']]['delta'] = rev_reg_delta_json
            prover['cred'] = cred_json
            # 11. Prover store Credential
            cred = json.loads(prover['cred'])
            prover['rev_reg_id'] = cred['rev_reg_id']
            prover['rev_reg_def'] = store[prover['rev_reg_id']]['definition']
            prover['rev_reg_delta'] = store[prover['rev_reg_id']]['delta']

            await anoncreds.prover_store_credential(prover['wallet'], None, prover['cred_req_metadata'],
                                                    prover['cred'], prover['cred_def'], prover['rev_reg_def'])
            try:
                # 10. Verifier builds Proof Request
                nonce = await anoncreds.generate_nonce()
                timestamp = int(time.time())
                verifier['proof_req'] = json.dumps({
                    'nonce': nonce,
                    'name': 'proof_req_1',
                    'version': '0.1',
                    'requested_attributes': {
                        'attr1_referent': {'name': 'name'}
                    },
                    'requested_predicates': {
                        'predicate1_referent': {'name': 'age', 'p_type': '>=', 'p_value': 18}
                    },
                    "non_revoked": {"to": timestamp}
                })
                prover['proof_req'] = verifier['proof_req']

                # Prover gets Credentials for Proof Request
                prover['cred_search_handle'] = \
                    await anoncreds.prover_search_credentials_for_proof_req(prover['wallet'], prover['proof_req'], None)

                # Prover gets Credentials for attr1_referent
                creds_for_attr1 = await anoncreds.prover_fetch_credentials_for_proof_req(prover['cred_search_handle'],
                                                                                         'attr1_referent', 10)
                prover['cred_for_attr1'] = json.loads(creds_for_attr1)[0]['cred_info']

                # Prover gets Credentials for predicate1_referent
                creds_for_predicate1 = await anoncreds.prover_fetch_credentials_for_proof_req(
                    prover['cred_search_handle'],
                    'predicate1_referent', 10)
                prover['cred_for_predicate1'] = json.loads(creds_for_predicate1)[0]['cred_info']

                await anoncreds.prover_close_credentials_search_for_proof_req(prover['cred_search_handle'])

                # 12. Prover creates revocation state
                prover['tails_reader_config'] = json.dumps(
                    {'base_dir': str(path_home().joinpath("tails")), 'uri_pattern': ''})
                prover['blob_storage_reader'] = await blob_storage.open_reader('default', prover['tails_reader_config'])

                rev_state_json = await anoncreds.create_revocation_state(prover['blob_storage_reader'],
                                                                         prover['rev_reg_def'],
                                                                         prover['rev_reg_delta'], timestamp,
                                                                         prover['cred_for_attr1']['cred_rev_id'])

                # 13. Prover create Proof for Proof Request
                prover['requested_creds'] = json.dumps({
                    'self_attested_attributes': {},
                    'requested_attributes': {'attr1_referent': {
                        'cred_id': prover['cred_for_attr1']['referent'], 'revealed': True, 'timestamp': timestamp}
                    },
                    'requested_predicates': {
                        'predicate1_referent': {'cred_id': prover['cred_for_predicate1']['referent'],
                                                'timestamp': timestamp}
                    }
                })

                schemas_json = json.dumps({prover['schema_id']: json.loads(prover['schema'])})
                cred_defs_json = json.dumps({prover['cred_def_id']: json.loads(prover['cred_def'])})
                revoc_states_json = json.dumps({prover['rev_reg_id']: {timestamp: json.loads(rev_state_json)}})

                prover['proof'] = \
                    await anoncreds.prover_create_proof(prover['wallet'], prover['proof_req'],
                                                        prover['requested_creds'],
                                                        prover['master_secret_id'], schemas_json, cred_defs_json,
                                                        revoc_states_json)
                verifier['proof'] = prover['proof']

                # 12. Verifier verify proof
                proof = json.loads(verifier['proof'])
                assert 'Alex' == proof['requested_proof']['revealed_attrs']['attr1_referent']['raw']

                identifier = proof['identifiers'][0]

                verifier['cred_def_id'] = identifier['cred_def_id']
                verifier['schema_id'] = identifier['schema_id']
                verifier['rev_reg_id'] = identifier['rev_reg_id']

                verifier['cred_def'] = store[verifier['cred_def_id']]
                verifier['schema'] = store[verifier['schema_id']]
                verifier['rev_reg_def'] = store[verifier['rev_reg_id']]['definition']
                verifier['rev_reg_value'] = store[verifier['rev_reg_id']]['delta']

                schemas_json = json.dumps({verifier['schema_id']: json.loads(verifier['schema'])})
                cred_defs_json = json.dumps({verifier['cred_def_id']: json.loads(verifier['cred_def'])})
                revoc_ref_defs_json = json.dumps({verifier['rev_reg_id']: json.loads(verifier['rev_reg_def'])})
                revoc_regs_json = json.dumps(
                    {verifier['rev_reg_id']: {timestamp: json.loads(verifier['rev_reg_value'])}})

                assert await anoncreds.verifier_verify_proof(verifier['proof_req'], verifier['proof'], schemas_json,
                                                             cred_defs_json,
                                                             revoc_ref_defs_json, revoc_regs_json)
            finally:
                await wallet.close_wallet(issuer['wallet'])
                # 18.
                await wallet.delete_wallet(issuer['wallet_config'], issuer['wallet_credentials'])

        finally:
            # 17.
            await wallet.close_wallet(prover['wallet'])
            # 18.
            await wallet.delete_wallet(prover['wallet_config'], prover['wallet_credentials'])
    finally:
        await close_pool(pool_handle)
