from .wallet import WalletConnection, WalletItemNotFound


async def create_and_store_my_did(wallet: WalletConnection):
    """ Create and store my DID, adding a map from verkey to DID using the
        non_secrets API.
    """
    (my_did, my_vk) = await wallet.create_and_store_my_did()
    await wallet.add_wallet_record('key-to-did', my_vk, my_did)
    return my_did, my_vk


async def store_their_did(wallet: WalletConnection, their_did, their_vk):
    """ Store their did, adding a map from verkey to DID using the non_secrets
        API.
    """
    await wallet.store_their_did(their_did, their_vk)
    await wallet.add_wallet_record('key-to-did', their_vk, their_did)


async def did_for_key(wallet: WalletConnection, key):
    """ Retrieve DID for a given key from the non_secrets verkey to DID map.
    """
    try:
        did = await wallet.get_wallet_record('key-to-did', key)
        return did
    except WalletItemNotFound:
        return None
