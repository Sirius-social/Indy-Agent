import logging
import json
import asyncio

import pytest

from core.wallet import WalletConnection
from core.base import ReadOnlyChannel, WriteOnlyChannel
from core.aries_rfcs.features.feature_0023_did_exchange.feature import *


@pytest.mark.asyncio
@pytest.mark.django_db
async def test_invitee_state_machine():
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
                msg = await DIDExchange.generate_invite_message(
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
            inviter_state_machine = DIDExchange.InviterStateMachine('inviter_state_machine')
            inviter_state_machine.label = 'Inviter'
            inviter_state_machine.endpoint = inviter_endpoint.name
            invitee_state_machine = DIDExchange.InviteeStateMachine('invitee_state_machine')
            invitee_state_machine.label = 'Invitee'
            invitee_state_machine.endpoint = invitee_endpoint.name
            # invitee received invite message
            await invitee_state_machine.invoke(
                DIDExchange.MESSAGE_CONTENT_TYPE, invite_msg.as_json(), invitee_wallet
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
            await invitee_state_machine.invoke(
                content_type, wire_message, invitee_wallet
            )
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
