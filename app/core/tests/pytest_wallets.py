import pytest

from core.wallet import *


@pytest.mark.asyncio
async def test_wallet_connection():
    agent_name = 'test-agent'
    pass_phrase = 'pass_phrase'
    conn = WalletConnection(agent_name, pass_phrase, ephemeral=True)

    await conn.connect()

    assert conn.initialized is True
    await conn.disconnect()
    assert conn.initialized is False


@pytest.mark.asyncio
async def test_wallet_create_did():
    agent_name = 'test-agent'
    pass_phrase = 'pass_phrase'
    conn = WalletConnection(agent_name, pass_phrase, ephemeral=True)
    await conn.connect()
    try:
        did, verkey = await conn.create_and_store_my_did()
        assert did
        assert verkey
    finally:
        await conn.disconnect()


@pytest.mark.asyncio
async def test_wallet_create_key():
    agent_name = 'test-agent'
    pass_phrase = 'pass_phrase'
    conn = WalletConnection(agent_name, pass_phrase, ephemeral=True)
    await conn.connect()
    try:
        key1 = await conn.create_key()
        assert key1
    finally:
        conn.disconnect()


@pytest.mark.asyncio
async def test_async_wallet_multiple_conn():
    agent_name = 'test-agent'
    pass_phrase = 'pass_phrase'
    conn1 = await MultiConnWallet.connect(agent_name, pass_phrase)
    conn2 = await MultiConnWallet.connect(agent_name, pass_phrase)
    try:
        pass
    finally:
        await conn1.disconnect()


@pytest.mark.asyncio
async def test_async_wallet_sane():
    agent_name = 'test-agent'
    pass_phrase = 'pass_phrase'
    conn = await MultiConnWallet.connect(agent_name, pass_phrase)
    try:
        did, verkey = await conn.create_and_store_my_did()
        assert did
        assert verkey
        key = await conn.create_key()
        assert key
    finally:
        await conn.disconnect()
