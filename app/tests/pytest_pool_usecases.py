import json
import pprint
import logging

import pytest
from indy import pool, ledger, wallet, did
from indy.error import IndyError, ErrorCode


GENESIS_FILE_PATH = '/ci/pool_transactions_genesis'
PROTOCOL_VERSION = 2
TEST_POOL_NAME = 'pool'


# logging.getLogger().setLevel(logging.DEBUG)


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
            print_log('Matching: ', verkey_from_ledger == trust_anchor_verkey)
        finally:
            print_log('\nClosing wallet\n')
            await wallet.close_wallet(wallet_handle)
            await wallet.delete_wallet(wallet_config, wallet_credentials)
    finally:
        await close_pool(pool_handle)
    pass
