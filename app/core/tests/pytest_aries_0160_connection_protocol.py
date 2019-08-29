import asyncio

import pytest
from django.db import connection
from channels.db import database_sync_to_async

from core.wallet import WalletConnection, WalletAgent
from core.base import ReadOnlyChannel, WriteOnlyChannel
from core.aries_rfcs.features.feature_0160_connection_protocol.feature import *
from state_machines.base import MachineIsDone


def remove_agent_databases(*names):
    with connection.cursor() as cursor:
        for name in names:
            db_name = WalletConnection.make_wallet_address(name)
            cursor.execute("DROP DATABASE  IF EXISTS %s" % db_name)


@pytest.mark.asyncio
@pytest.mark.django_db
async def test_state_machines():
    await database_sync_to_async(remove_agent_databases)('inviter', 'invitee')
    inviter_wallet = WalletConnection('inviter', 'pass')
    invitee_wallet = WalletConnection('invitee', 'pass')
    inviter_endpoint = await ReadOnlyChannel.create('inviter')
    invitee_endpoint = await ReadOnlyChannel.create('invitee')

    await inviter_wallet.create()
    await invitee_wallet.create()
    try:
        # step 1: generate invite message
        invite_msg = None

        async def generator():
            await asyncio.sleep(0.5)
            await WalletAgent.open('inviter', 'pass')
            try:
                msg = await ConnectionProtocol.generate_invite_message(
                    'Inviter',
                    inviter_endpoint.name,
                    'inviter',
                    'pass'
                )
                nonlocal invite_msg
                invite_msg = msg
            finally:
                await WalletAgent.close('inviter', 'pass')

        await asyncio.wait([generator(), WalletAgent.process('inviter')], timeout=5)
        assert invite_msg is not None
        print('\n--- Invite message --------------------------------------------------------\n')
        print(invite_msg.pretty_print())
        print('\n---------------------------------------------------------------------------\n')
        asyncio.sleep(1)

        await inviter_wallet.open()
        await invitee_wallet.open()
        try:
            # check pairwise lists
            inviter_pairwise_list = await inviter_wallet.list_pairwise()
            invitee_pairwise_list = await invitee_wallet.list_pairwise()
            assert len(inviter_pairwise_list) == 0
            assert len(invitee_pairwise_list) == 0
            # Setup state machines
            inviter_state_machine = ConnectionProtocol.ConnProtocolInviterStateMachine('inviter_state_machine')
            inviter_state_machine.label = 'Inviter'
            inviter_state_machine.endpoint = inviter_endpoint.name
            invitee_state_machine = ConnectionProtocol.ConnProtocolInviteeStateMachine('invitee_state_machine')
            invitee_state_machine.label = 'Invitee'
            invitee_state_machine.endpoint = invitee_endpoint.name
            invitee_state_machine.log_channel_name = 'xxx'
            # invitee received invite message
            await invitee_state_machine.invoke(
                ConnectionProtocol.MESSAGE_CONTENT_TYPE, invite_msg.as_json(), invitee_wallet
            )
            success, data = await inviter_endpoint.read(timeout=10)
            assert success is True
            content_type, wire_message = data
            wire_message = wire_message.encode()
            assert content_type == EndpointTransport.DEFAULT_WIRE_CONTENT_TYPE
            # inviter receive connection request
            await inviter_state_machine.invoke(
                content_type, wire_message, inviter_wallet
            )
            success, data = await invitee_endpoint.read(timeout=10)
            assert success is True
            content_type, wire_message = data
            wire_message = wire_message.encode()
            assert content_type == EndpointTransport.DEFAULT_WIRE_CONTENT_TYPE
            # Invitee receive connection response
            try:
                await invitee_state_machine.invoke(
                    content_type, wire_message, invitee_wallet
                )
            except MachineIsDone:
                pass
            else:
                raise RuntimeError('Unexpected termination')
            success, data = await inviter_endpoint.read(timeout=10)
            assert success is True
            content_type, wire_message = data
            wire_message = wire_message.encode()
            assert content_type == EndpointTransport.DEFAULT_WIRE_CONTENT_TYPE
            # Inviter receive ack
            try:
                await inviter_state_machine.invoke(
                    content_type, wire_message, inviter_wallet
                )
            except MachineIsDone:
                pass
            else:
                raise RuntimeError('Unexpected termination')
            # check pairwise lists
            inviter_pairwise_list = await inviter_wallet.list_pairwise()
            invitee_pairwise_list = await invitee_wallet.list_pairwise()
            assert len(inviter_pairwise_list) == 1
            assert len(invitee_pairwise_list) == 1
        finally:
            await inviter_wallet.close()
            await invitee_wallet.close()
    finally:
        await inviter_wallet.delete()
        await invitee_wallet.delete()


@pytest.mark.asyncio
@pytest.mark.django_db
async def test_feature_interfaces():
    await database_sync_to_async(remove_agent_databases)('inviter', 'invitee')
    inviter_wallet = WalletConnection('inviter', 'pass')
    invitee_wallet = WalletConnection('invitee', 'pass')
    inviter_endpoint = await ReadOnlyChannel.create('inviter')
    invitee_endpoint = await ReadOnlyChannel.create('invitee')

    await inviter_wallet.create()
    await invitee_wallet.create()
    try:
        asyncio.ensure_future(WalletAgent.process('inviter'))
        asyncio.ensure_future(WalletAgent.process('invitee'))
        await asyncio.sleep(10)
        await WalletAgent.open('inviter', 'pass')
        await WalletAgent.open('invitee', 'pass')
        try:
            # Step 1: generate invitation link
            link, msg = await ConnectionProtocol.generate_invite_link(
                'Inviter',
                inviter_endpoint.name,
                'inviter',
                'pass'
            )
            invite_link = 'http://example.com/invitations' + link
            print('\n--- Invite Link --------------------------------------------------------\n')
            print(invite_link)
            print('\n------------------------------------------------------------------------\n')
            # check pairwise lists
            inviter_pairwise_list = await WalletAgent.list_pairwise('inviter', 'pass')
            invitee_pairwise_list = await WalletAgent.list_pairwise('invitee', 'pass')
            assert len(inviter_pairwise_list) == 0
            assert len(invitee_pairwise_list) == 0
            # Invitee received invitation link
            log_channel = await ConnectionProtocol.receive_invite_link(
                invite_link, 'invitee', 'pass', 'Invitee', invitee_endpoint.name, 10
            )
            assert type(log_channel) is str
            # Wait answer (connection request) on Inviter endpoint
            success, data = await inviter_endpoint.read(timeout=10)
            assert success is True
            content_type, wire_message = data
            wire_message = wire_message.encode()
            ok = await ConnectionProtocol.handle('inviter', wire_message, 'Inviter', inviter_endpoint.name)
            assert ok is True
            # Wait answer (connection response) on Invitee endpoint
            success, data = await invitee_endpoint.read(timeout=10)
            assert success is True
            content_type, wire_message = data
            wire_message = wire_message.encode()
            # Emulate Invitee receiving connection response
            ok = await ConnectionProtocol.handle('invitee', wire_message, 'Invitee', invitee_endpoint.name)
            assert ok is True
            success, data = await inviter_endpoint.read(timeout=10)
            assert success is True
            content_type, wire_message = data
            wire_message = wire_message.encode()
            # Emulate Inviter received ack message
            ok = await ConnectionProtocol.handle('inviter', wire_message, 'Inviter', inviter_endpoint.name)
            assert ok is True
            await asyncio.sleep(1)
            inviter_pairwise_list = await WalletAgent.list_pairwise('inviter', 'pass')
            invitee_pairwise_list = await WalletAgent.list_pairwise('invitee', 'pass')
            assert len(inviter_pairwise_list) == 1
            assert len(invitee_pairwise_list) == 1
        finally:
            await WalletAgent.close('inviter', 'pass')
            await WalletAgent.close('invitee', 'pass')
            await asyncio.sleep(1)
    finally:
        pass
