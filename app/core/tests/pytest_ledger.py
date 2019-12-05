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
async def test_wallet_write_read_attributes():
    agent1_name = 'test-wallet-agent-1'
    agent2_name = 'test-wallet-agent-2'
    agent3_name = 'test-wallet-agent-3'
    pass_phrase = 'pass_phrase'

    await remove_wallets(agent1_name, agent2_name, agent3_name)
    conn1 = WalletConnection(agent1_name, pass_phrase)
    conn2 = WalletConnection(agent2_name, pass_phrase)
    conn3 = WalletConnection(agent3_name, pass_phrase)
    await conn1.create()
    await conn2.create()
    await conn3.create()
    try:
        async def tests():
            asyncio.sleep(0.5)
            ping1 = await WalletAgent.ping(agent1_name)
            assert ping1 is True
            ping2 = await WalletAgent.ping(agent2_name)
            assert ping2 is True
            ping3 = await WalletAgent.ping(agent3_name)
            assert ping3 is True
            await WalletAgent.open(agent1_name, pass_phrase)
            await WalletAgent.open(agent2_name, pass_phrase)
            await WalletAgent.open(agent3_name, pass_phrase)
            try:
                did_steward, verkey_steward = await WalletAgent.create_and_store_my_did(agent1_name, pass_phrase, '000000000000000000000000Steward1')
                did_owner, vk_owner = await WalletAgent.create_and_store_my_did(agent2_name, pass_phrase)
                # send nym
                nym_request = await WalletAgent.build_nym_request(
                    agent1_name, pass_phrase, did_steward, did_owner, vk_owner, role='TRUST_ANCHOR'
                )
                nym_response = await WalletAgent.sign_and_submit_request(
                    agent_name=agent1_name,
                    pass_phrase=pass_phrase,
                    self_did=did_steward,
                    request_json=nym_request
                )
                assert nym_response['op'] == 'REPLY'
                # attrib request
                attrib_request = await WalletAgent.build_attrib_request(
                    agent_name=agent2_name,
                    pass_phrase=pass_phrase,
                    self_did=did_owner,
                    target_did=did_owner,
                    raw={
                        'attrib': {
                            'field1': 'field-value-1',
                            'field2': 'field-value-2',
                        }
                    }
                )
                attrib_response = await WalletAgent.sign_and_submit_request(
                    agent_name=agent2_name,
                    pass_phrase=pass_phrase,
                    self_did=did_owner,
                    request_json=attrib_request
                )
                assert attrib_response['op'] == 'REPLY'
                # get attrib request
                did_reader, vk_reader = await WalletAgent.create_and_store_my_did(agent3_name, pass_phrase)
                get_attrib_request = await WalletAgent.build_get_attrib_request(
                    agent_name=agent2_name,
                    pass_phrase=pass_phrase,
                    self_did=did_reader,
                    target_did=did_owner,
                    raw='attrib'
                )
                get_attrib_response = await WalletAgent.sign_and_submit_request(
                    agent_name=agent3_name,
                    pass_phrase=pass_phrase,
                    self_did=did_reader,
                    request_json=get_attrib_request
                )
                assert get_attrib_response['op'] == 'REPLY'
                data_str = str(get_attrib_response['result']['data'])
                assert 'field-value-1' in data_str
                assert 'field-value-2' in data_str
            finally:
                await WalletAgent.close(agent1_name, pass_phrase)
                await WalletAgent.close(agent2_name, pass_phrase)
                await WalletAgent.close(agent3_name, pass_phrase)

        done, pending = await asyncio.wait(
            [tests(), WalletAgent.process(agent1_name), WalletAgent.process(agent2_name), WalletAgent.process(agent3_name)],
            timeout=500  # 5
        )
        for f in pending:
            f.cancel()
        for f in done:
            if f.exception():
                raise f.exception()
    finally:
        await conn1.delete()
        await conn2.delete()
        await conn3.delete()
