import json
import asyncio
from urllib.parse import parse_qs

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from rest_framework import status

from core.base import ReadOnlyChannel
from core.wallet import WalletAgent, BaseWalletException
from transport.utils import make_wallet_wired_messages_channel_name


class WalletStatusNotification(AsyncJsonWebsocketConsumer):

    def __init__(self, *args, **kwargs):
        self.listener_log = None
        self.listener_wired = None
        self.agent_name = kwargs.get('agent_name')
        self.pass_phrase = kwargs.get('pass_phrase')
        self.close_raised = False
        super().__init__(*args, **kwargs)

    async def connect(self):
        wallet, pass_phrase = self.extract_wallet_credentials()
        self.agent_name = wallet
        self.pass_phrase = pass_phrase
        try:
            await WalletAgent.ensure_agent_is_open(wallet, pass_phrase)
            chan_log = await WalletAgent.access_log(wallet, pass_phrase)
            chan_wired = await ReadOnlyChannel.create(
                make_wallet_wired_messages_channel_name(self.agent_name)
            )
        except BaseWalletException as e:
            await self.close(code=e.error_message)
        else:
            self.listener_log = asyncio.ensure_future(self.listen_log(chan_log))
            self.listener_wired = asyncio.ensure_future(self.listen_wired(chan_wired))
            await self.accept()
    pass

    async def receive_json(self, content, **kwargs):
        if content.get('topic') == 'write_log':
            message = content.get('data', {}).get('message')
            details = content.get('data', {}).get('details')
            await WalletAgent.write_log(self.agent_name, self.pass_phrase, message, details)

    async def listen_log(self, channel: ReadOnlyChannel):
        try:
            while True:
                not_closed, data = await channel.read(timeout=None)
                if not_closed:
                    topic, details = data
                    await self.send_notification(topic, details)
                else:
                    await self.send_notification(topic='Wallet is closed')
                    return
        finally:
            await self.close()
            await channel.close()

    async def listen_wired(self, channel: ReadOnlyChannel):
        try:
            while True:
                not_closed, data = await channel.read(timeout=None)
                if not_closed:
                    print('------- WIRED MSG --------')
                    print(json.dumps(data, indent=4))
                    print('--------------------------')
                    pass
                else:
                    return
        finally:
            await self.close()
            await channel.close()

    async def disconnect(self, code):
        if self.listener_log:
            self.listener_log.cancel()
        if self.listener_wired:
            self.listener_wired.cancel()

    async def close(self, code=None):
        if not self.close_raised:
            await super().close(code)
            self.close_raised = True
        else:
            pass

    async def send_notification(self, topic: str, data: dict=None):
        await self.send_json(dict(topic=topic, data=data))

    async def send_error_report(self, error_code: int, error_message: str):
        await self.send_notification(topic='error', data=dict(error_code=error_code, error_message=error_message))

    def extract_wallet_credentials(self):
        query_string = self.scope['query_string'].decode('utf-8').lower()
        wallet = parse_qs(query_string).get('wallet')
        wallet = wallet[0] if type(wallet) is list else wallet
        pass_phrase = parse_qs(query_string).get('pass_phrase')
        pass_phrase = pass_phrase[0] if type(pass_phrase) is list else pass_phrase
        return wallet, pass_phrase
