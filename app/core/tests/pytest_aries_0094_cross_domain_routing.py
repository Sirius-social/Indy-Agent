import pytest
from django.db import connection
from channels.db import database_sync_to_async

from core.wallet import *
from core.messages.message import Message
from core.aries_rfcs.features.feature_0095_basic_message.feature import BasicMessage
from core.aries_rfcs.concepts.concept_0094_cross_domain.concept import RoutingMessage


async def remove_wallets(*names):

    def remove_wallets_sync(*wallet_names):
        with connection.cursor() as cursor:
            for name in wallet_names:
                db_name = WalletConnection.make_wallet_address(name)
                cursor.execute("DROP DATABASE  IF EXISTS %s" % db_name)

    await database_sync_to_async(remove_wallets_sync)(*names)


@pytest.mark.asyncio
@pytest.mark.django_db
async def test_forwarding_message():
    wallet1_name = 'test_wallet_1'
    wallet2_name = 'test_wallet_2'
    pass_phrase = 'pass_phrase'
    await remove_wallets(wallet1_name, wallet2_name)

    conn_sender = WalletConnection(wallet1_name, pass_phrase)
    conn_recipient = WalletConnection(wallet2_name, pass_phrase)
    await conn_sender.create()
    await conn_recipient.create()
    try:
        await conn_sender.open()
        await conn_recipient.open()
        # build expected message
        message = BasicMessage.build(content='Test content')
        # generate keys
        sender_verkey = await conn_sender.create_key()
        recipient_verkey = await conn_recipient.create_key()
        routing_key1 = await conn_recipient.create_key()
        routing_key2 = await conn_recipient.create_key()
        routing_keys = [routing_key1, routing_key2]
        print('-------- values ----------')
        print('sender_verkey: ' + sender_verkey)
        print('recipient_verkey: ' + recipient_verkey)
        print('routing_keys: ' + str(routing_keys))
        print('--------------------------')
        # emulate communication
        wired = await RoutingMessage.pack(message, conn_sender, recipient_verkey, routing_keys, sender_verkey)
        unpacked = await conn_recipient.unpack_message(wired)
        kwargs = json.loads(unpacked['message'])
        message = Message(**kwargs)
        assert message.type == RoutingMessage.FORWARD
        assert unpacked.get('recipient_verkey') == routing_key2
        assert unpacked.get('sender_verkey') is None
        assert message.data.get('to') == routing_key1

        message, recipient_vk, sender_vk = await RoutingMessage.unpack(message, conn_recipient)
        assert message.type == RoutingMessage.FORWARD
        assert recipient_vk == routing_key1
        assert sender_vk is None
        assert message.data.get('to') == recipient_verkey

        message, recipient_vk, sender_vk = await RoutingMessage.unpack(message, conn_recipient)
        assert message.type == BasicMessage.MESSAGE
        assert recipient_vk == recipient_verkey
        assert sender_vk == sender_verkey
        assert message.data.get('content') == 'Test content'
    finally:
        await conn_sender.delete()
        await conn_recipient.delete()
