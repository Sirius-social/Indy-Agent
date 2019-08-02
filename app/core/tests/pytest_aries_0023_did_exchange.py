import logging
import json
import asyncio

import pytest

from core.wallet import WalletConnection
from core.base import ReadOnlyChannel, WriteOnlyChannel
from core.aries_rfcs.features.feature_0023_did_exchange.feature import *


@pytest.mark.asyncio
@pytest.mark.django_db
async def test_inviter_state_machine():
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
                    'http://myendpoint.com/xxx',
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
            inviter_state_machine = DIDExchange.InviterStateMachine('inviter_state_machine')
            invitee_state_machine = DIDExchange.InviteeStateMachine('invitee_state_machine')
            # Invitee state machine will make response to channel
            response_chan = await ReadOnlyChannel.create(invitee_state_machine.get_id())
            # invitee received invite message
            await invitee_state_machine.invoke(
                DIDExchange.MESSAGE_CONTENT_TYPE, invite_msg.as_json(), invitee_wallet
            )
            succ, data = await response_chan.read(timeout=10)
            assert succ is True
            connection_request = Message(**json.loads(data))
            print('\n--- Connection Request --------------------------------------------------------\n')
            print(connection_request.pretty_print())
            print('\n---------------------------------------------------------------------------\n')
            succ, _ = await response_chan.read(timeout=1)
            assert succ is False
        finally:
            await inviter_wallet.close()
            await invitee_wallet.close()
    finally:
        await inviter_wallet.delete()
        await invitee_wallet.delete()
