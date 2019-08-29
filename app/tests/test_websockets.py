import os
import uuid
import json
import threading
from time import sleep
from unittest import skip

import requests
import websocket
from channels.testing import ChannelsLiveServerTestCase
from channels.db import database_sync_to_async
from django.db import connection
from django.test import override_settings
from django.conf import settings

from core.wallet import WalletConnection
from core.sync2async import run_async
from api.models import Wallet
from authentication.models import AgentAccount


class WebSocketsTest(ChannelsLiveServerTestCase):

    URL_BASE = '/ws/wallets/status/'
    IDENTITY = 'test'
    PASS = 'test'
    WALLET_UID = 'test_wallet'
    PASS_PHRASE = 'pass'

    def setUp(self):
        self.ws = websocket.WebSocket()
        self.server_url = self.live_server_url
        self.server_url = self.server_url.replace('http://', 'ws://')
        self.server_url = self.server_url.replace('https://', 'ws://')
        self.account = AgentAccount.objects.create(username=self.IDENTITY, is_active=True, is_staff=True)
        self.account.set_password(self.PASS)
        self.account.save()
        self.assertTrue(self.account.check_password(self.PASS))
        self.wallet = None
        run_async(self.create_wallet())
        super().setUp()
    pass

    def tearDown(self):
        os.popen("pkill -f run_wallet_agent")
        sleep(1)
        run_async(self.delete_wallet())
        sleep(1)
    pass

    async def create_wallet(self):

        def clean():
            with connection.cursor() as cursor:
                cursor.execute("DROP DATABASE  IF EXISTS %s" % self.WALLET_UID)

        await database_sync_to_async(clean)()

        self.wallet = WalletConnection(self.WALLET_UID, self.PASS_PHRASE)
        await self.wallet.create()

        def create_db_model():
            Wallet.objects.create(uid=self.WALLET_UID, owner=self.account)

        await database_sync_to_async(create_db_model)()
    pass

    async def delete_wallet(self):
        await self.wallet.delete()

    def ws_read_json(self, timeout=5):

        ret = None
        ev = threading.Event()

        def routine(ws):
            nonlocal ret
            ret = json.loads(ws.recv())
            ev.set()

        th = threading.Thread(target=routine, args=(self.ws,))
        th.daemon = True
        th.start()
        if ev.wait(timeout):
            return ret
        else:
            raise TimeoutError()

    def test_sane(self):
        url = self.server_url + self.URL_BASE + '?wallet=%s&pass_phrase=%s' % (self.WALLET_UID, self.PASS_PHRASE)
        self.ws.connect(url)
        self.assertTrue(self.ws.connected)
        cmd = dict(
            command='write_log',
            params=dict(message='test-message', details={'marker': uuid.uuid4().hex})
        )
        self.ws.send(json.dumps(cmd))
        answer = self.ws_read_json()
        self.ws.close()
        self.assertEqual(cmd['params']['message'], answer['topic'])
        self.assertDictEqual(cmd['params']['details'], answer['data'])
        pass
