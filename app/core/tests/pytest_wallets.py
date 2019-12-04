import asyncio
from time import sleep

import pytest
from django.db import connection
from channels.db import database_sync_to_async

from core.wallet import *
from core.models import *
from state_machines.base import *


async def remove_wallets(*names):

    def remove_wallets_sync(*wallet_names):
        with connection.cursor() as cursor:
            for name in wallet_names:
                db_name = WalletConnection.make_wallet_address(name)
                cursor.execute("DROP DATABASE  IF EXISTS %s" % db_name)

    await database_sync_to_async(remove_wallets_sync)(*names)


@pytest.mark.asyncio
@pytest.mark.django_db
async def test_wallet_sane():
    agent_name = 'test_wallet_sane'
    pass_phrase = 'pass_phrase'
    await remove_wallets(agent_name)

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
@pytest.mark.django_db
async def test_wallet():
    agent_name = 'test-agent'
    pass_phrase = 'pass_phrase'
    await remove_wallets(agent_name)
    conn = WalletConnection(agent_name, pass_phrase, ephemeral=True)

    await conn.connect()

    assert conn.is_open is True
    await conn.close()
    assert conn.is_open is False


@pytest.mark.asyncio
@pytest.mark.django_db
async def test_wallet_did():
    agent_name = 'test-agent'
    pass_phrase = 'pass_phrase'
    await remove_wallets(agent_name)
    conn = WalletConnection(agent_name, pass_phrase, ephemeral=True)
    await conn.connect()
    try:
        did, verkey = await conn.create_and_store_my_did()
        assert did
        assert verkey
        meta = {'label': 'value'}
        await conn.set_did_metadata(did, meta)
        actual = await conn.get_did_metadata(did)
        assert meta == actual
        actual = await conn.key_for_local_did(did)
        assert verkey == actual
    finally:
        await conn.close()


@pytest.mark.asyncio
@pytest.mark.django_db
async def test_wallet_create_key():
    agent_name = 'test-agent'
    pass_phrase = 'pass_phrase'
    await remove_wallets(agent_name)
    conn = WalletConnection(agent_name, pass_phrase, ephemeral=True)
    await conn.connect()
    try:
        key1 = await conn.create_key()
        assert key1
    finally:
        await conn.close()


@pytest.mark.asyncio
@pytest.mark.django_db
async def test_wallet_records():
    agent_name = 'test-agent-records'
    pass_phrase = 'pass_phrase'
    await remove_wallets(agent_name)
    conn = WalletConnection(agent_name, pass_phrase, ephemeral=True)
    await conn.connect()
    try:
        type_ = 'connection_key'
        id_ = 'connection_key_value'
        value = 'connection_key_value'
        await conn.add_wallet_record(type_, id_, value)
        actual = await conn.get_wallet_record(type_, id_)
        assert value == actual
        new_value = 'new-value'
        await conn.update_wallet_record_value(type_, id_, new_value)
        actual = await conn.get_wallet_record(type_, id_)
        assert new_value == actual
    finally:
        await conn.close()


@pytest.mark.asyncio
@pytest.mark.django_db
async def test_wallet_agent_sane():
    agent_name = 'test_wallet_agent_sane'
    pass_phrase = 'pass_phrase'

    await remove_wallets(agent_name)
    conn = WalletConnection(agent_name, pass_phrase)
    await conn.create()
    try:
        async def tests():
            asyncio.sleep(5)
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
                actual = await WalletAgent.key_for_local_did(agent_name, pass_phrase, did)
                assert verkey == actual
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


@pytest.mark.asyncio
@pytest.mark.django_db
async def test_wallet_agent_records():
    agent_name = 'test-wallet-agent-records'
    pass_phrase = 'pass_phrase'

    await remove_wallets(agent_name)
    conn = WalletConnection(agent_name, pass_phrase)
    await conn.create()
    try:
        async def tests():
            asyncio.sleep(0.5)
            ping = await WalletAgent.ping(agent_name)
            assert ping is True
            await WalletAgent.open(agent_name, pass_phrase)
            try:
                type_ = 'connection_key'
                id_ = 'connection_key_value'
                value = 'connection_key_value'
                await WalletAgent.add_wallet_record(agent_name, pass_phrase, type_, id_, value)
                actual = await WalletAgent.get_wallet_record(agent_name, pass_phrase, type_, id_)
                assert value == actual
                new_value = 'new-value'
                await WalletAgent.update_wallet_record_value(agent_name, pass_phrase, type_, id_, new_value)
                actual = await WalletAgent.get_wallet_record(agent_name, pass_phrase, type_, id_)
                assert new_value == actual
            finally:
                await WalletAgent.close(agent_name, pass_phrase)

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


@pytest.mark.asyncio
@pytest.mark.django_db
async def test_wallet_pack_unpack():
    agent1_name = 'test-wallet-agent-1'
    agent2_name = 'test-wallet-agent-2'
    pass_phrase = 'pass_phrase'

    await remove_wallets(agent1_name, agent2_name)
    conn1 = WalletConnection(agent1_name, pass_phrase)
    conn2 = WalletConnection(agent2_name, pass_phrase)
    await conn1.create()
    await conn2.create()
    try:
        async def tests():
            asyncio.sleep(0.5)
            ping1 = await WalletAgent.ping(agent1_name)
            assert ping1 is True
            ping2 = await WalletAgent.ping(agent2_name)
            assert ping2 is True
            await WalletAgent.open(agent1_name, pass_phrase)
            await WalletAgent.open(agent2_name, pass_phrase)
            try:
                did_sender, vk_sender = await WalletAgent.create_and_store_my_did(agent1_name, pass_phrase)
                did_receiver, vk_receiver = await WalletAgent.create_and_store_my_did(agent2_name, pass_phrase)
                message = dict(content=uuid.uuid4().hex)
                # auth encrypt
                encrypted = await WalletAgent.pack_message(agent1_name, message, vk_receiver, vk_sender)
                print('---------- Auth encrypt -> encrypted ---------')
                print(str(encrypted))
                assert message['content'] not in str(encrypted)
                decrypted = await WalletAgent.unpack_message(agent2_name, encrypted)
                print('---------- Auth encrypt -> decrypted ---------')
                print(str(decrypted))
                assert message['content'] in str(decrypted)
                # anon encrypt
                encrypted = await WalletAgent.pack_message(agent1_name, message, vk_receiver)
                print('---------- Anon encrypt -> encrypted ---------')
                print(str(encrypted))
                assert message['content'] not in str(encrypted)
                decrypted = await WalletAgent.unpack_message(agent2_name, encrypted)
                assert message['content'] in str(decrypted)
                print('---------- Anon encrypt -> decrypted ---------')
                print(str(decrypted))
            finally:
                await WalletAgent.close(agent1_name, pass_phrase)
                await WalletAgent.close(agent2_name, pass_phrase)

        done, pending = await asyncio.wait(
            [tests(), WalletAgent.process(agent1_name), WalletAgent.process(agent2_name)],
            timeout=5
        )
        for f in pending:
            f.cancel()
        for f in done:
            if f.exception():
                raise f.exception()
    finally:
        await conn1.delete()
        await conn2.delete()


class TestMachine(BaseStateMachine, metaclass=InvokableStateMachineMeta):

    LOG = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    async def handle(self, content_type, data):
        TestMachine.LOG.append([content_type, data])
        pass


@pytest.mark.asyncio
@pytest.mark.django_db
async def test_wallet_invoke_machine():
    agent_name = 'test_wallet_invoke_machine'
    pass_phrase = 'pass_phrase'
    machine_id = 'some-id'

    await remove_wallets(agent_name)
    conn = WalletConnection(agent_name, pass_phrase)
    await conn.create()
    try:
        async def tests():
            await asyncio.sleep(5)
            try:
                await WalletAgent.open(agent_name, pass_phrase)
                await WalletAgent.start_state_machine(agent_name, TestMachine, machine_id)
                record = StartedStateMachine.objects.filter(machine_id=machine_id).first()
                assert record is not None
                assert record.machine_class_name == TestMachine.__name__
                await WalletAgent.invoke_state_machine(agent_name, machine_id, 'content_type', dict(value=2))
                await asyncio.sleep(1)
                assert len(TestMachine.LOG) > 0
                assert TestMachine.LOG[-1] == ['content_type', dict(value=2)]
            finally:
                await WalletAgent.close(agent_name, pass_phrase)

        done, pending = await asyncio.wait(
            [tests(), WalletAgent.process(agent_name)],
            timeout=10
        )
        for f in pending:
            f.cancel()
        for f in done:
            if f.exception():
                raise f.exception()
    finally:
        await conn.delete()


@pytest.mark.asyncio
@pytest.mark.django_db
async def test_wallet_agent_log_access():
    agent_name = 'test_wallet_access_log'
    pass_phrase = 'pass_phrase'

    await remove_wallets(agent_name)
    conn = WalletConnection(agent_name, pass_phrase)
    await conn.create()
    try:
        async def tests():
            await asyncio.sleep(5)
            try:
                await WalletAgent.open(agent_name, pass_phrase)
                channel = await WalletAgent.access_log(agent_name, pass_phrase)
                assert ':log' in channel.name
            finally:
                await WalletAgent.close(agent_name, pass_phrase)

        done, pending = await asyncio.wait(
            [tests(), WalletAgent.process(agent_name)],
            timeout=10
        )
        for f in pending:
            f.cancel()
        for f in done:
            if f.exception():
                raise f.exception()
    finally:
        await conn.delete()

