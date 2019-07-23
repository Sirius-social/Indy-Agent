import pytest

from core.wallet import *


@pytest.mark.asyncio
async def test_wallet_connection():
    agent_name = 'test-agent'
    pass_phrase = 'pass_phrase'
    conn = WalletConnection(agent_name, pass_phrase)

    await conn.connect()

    assert conn.initialized is True
    await conn.disconnect()
    assert conn.initialized is False


@pytest.mark.asyncio
async def test_wallet_create_did():
    agent_name = 'test-agent'
    pass_phrase = 'pass_phrase'
    conn = WalletConnection(agent_name, pass_phrase)
    await conn.connect()

    did, verkey = await conn.create_and_store_my_did()
    assert did
    assert verkey
