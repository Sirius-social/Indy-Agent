import asyncio
from time import sleep

import pytest

from core.wallet import *


@pytest.mark.asyncio
async def test_wallet_sane():
    agent_name = 'test_wallet_sane'
    pass_phrase = 'pass_phrase'

    conn = WalletConnection(agent_name, pass_phrase)
    with pytest.raises(WalletNotCreated):
        await conn.open()
    await conn.create()
    try:
        with pytest.raises(WalletAlreadyExists):
            await conn.create()
        await conn.open()
        assert conn.is_open is True
        assert conn.check_credentials(agent_name, 'invalid-pass') is False
        assert conn.check_credentials(agent_name, pass_phrase) is True
        await conn.close()
        assert conn.is_open is False
        # check open with other credentials
        conn2 = WalletConnection(agent_name, 'invalid-pass-phrase')
        with pytest.raises(WalletAccessDenied):
            await conn2.open()
    finally:
        await conn.delete()


@pytest.mark.asyncio
async def test_wallet():
    agent_name = 'test-agent'
    pass_phrase = 'pass_phrase'
    conn = WalletConnection(agent_name, pass_phrase, ephemeral=True)

    await conn.connect()

    assert conn.is_open is True
    await conn.close()
    assert conn.is_open is False


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
        await conn.close()


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
        conn.close()


@pytest.mark.asyncio
async def test_wallet_agent_sane():
    agent_name = 'test_wallet_agent_sane'
    pass_phrase = 'pass_phrase'

    conn = WalletConnection(agent_name, pass_phrase)
    await conn.create()
    try:
        async def tests():
            asyncio.sleep(0.5)
            ping = await WalletAgent.ping(agent_name)
            assert ping is True
            with pytest.raises(WalletAccessDenied):
                await WalletAgent.open(agent_name, 'invalid-pass')
            await WalletAgent.open(agent_name, pass_phrase)
            try:
                is_open = await WalletAgent.is_open(agent_name)
                assert is_open is True
                did, verkey = await WalletAgent.create_and_store_my_did(agent_name, pass_phrase)
                print('\nDID: ' + str(did))
                print('\mVERKEY: ' + str(verkey))
                assert did
                assert verkey
            finally:
                await WalletAgent.close(agent_name, pass_phrase)
            is_open = await WalletAgent.is_open(agent_name)
            assert is_open is False

        done, pending = await asyncio.wait(
            [tests(), WalletAgent.process(agent_name)],
            timeout=5
        )
        for f in pending:
            f.cancel()
        for f in done:
            if f.exception():
                raise f.exception()
    finally:
        await conn.delete()
