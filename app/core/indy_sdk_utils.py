import json

from core.const import *
from .wallet import WalletConnection, WalletItemNotFound


async def create_and_store_my_did(wallet: WalletConnection, seed=None):
    """ Create and store my DID, adding a map from verkey to DID using the
        non_secrets API.
    """
    (my_did, my_vk) = await wallet.create_and_store_my_did(seed=seed)
    try:
        await wallet.add_wallet_record(WALLET_KEY_TO_DID_KEY, my_vk, my_did)
    except:
        pass
    print(' ********* create_and_store_my_did **********')
    print('my_vk: ' + my_vk)
    print('my_did: ' + my_did)
    print('************************************')
    return my_did, my_vk


async def store_their_did(wallet: WalletConnection, their_did, their_vk):
    """ Store their did, adding a map from verkey to DID using the non_secrets
        API.
    """
    await wallet.store_their_did(their_did, their_vk)
    did = await did_for_key(wallet, their_vk)
    if not did:
        await wallet.add_wallet_record(WALLET_KEY_TO_DID_KEY, their_vk, their_did)


async def did_for_key(wallet: WalletConnection, key):
    """ Retrieve DID for a given key from the non_secrets verkey to DID map.
    """
    try:
        did = await wallet.get_wallet_record(WALLET_KEY_TO_DID_KEY, key)
        return did
    except WalletItemNotFound:
        return None


async def store_cred_def(wallet: WalletConnection, cred_def_id: str, body: dict):
    await delete_cred_def(wallet, cred_def_id)
    await wallet.add_wallet_record(WALLET_KEY_CRED_DEF, cred_def_id, json.dumps(body))


async def get_cred_def(wallet: WalletConnection, cred_def_id: str):
    try:
        value = await wallet.get_wallet_record(WALLET_KEY_CRED_DEF, cred_def_id)
    except WalletItemNotFound:
        return None
    else:
        return json.loads(value) if value else None


async def delete_cred_def(wallet: WalletConnection, cred_def_id: str):
    value = await get_cred_def(wallet, cred_def_id)
    if value:
        await wallet.delete_wallet_record(WALLET_KEY_CRED_DEF, cred_def_id)


async def store_issuer_schema(wallet: WalletConnection, schema_id: str, body: dict):
    await delete_issuer_schema(wallet, schema_id)
    await wallet.add_wallet_record(WALLET_KEY_ISSUER_SCHEMA, schema_id, json.dumps(body))


async def get_issuer_schema(wallet: WalletConnection, schema_id: str):
    try:
        value = await wallet.get_wallet_record(WALLET_KEY_ISSUER_SCHEMA, schema_id)
    except WalletItemNotFound:
        return None
    else:
        return json.loads(value) if value else None


async def delete_issuer_schema(wallet: WalletConnection, schema_id: str):
    value = await get_issuer_schema(wallet, schema_id)
    if value:
        await wallet.delete_wallet_record(WALLET_KEY_ISSUER_SCHEMA, schema_id)
