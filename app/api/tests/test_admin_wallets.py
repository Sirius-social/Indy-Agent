import requests
from requests.auth import HTTPBasicAuth
from channels.testing import ChannelsLiveServerTestCase
from django.urls import reverse
from django.db import connection

from authentication.models import AgentAccount
from api.models import Wallet
from transport.models import Endpoint


class AdminWalletsTest(ChannelsLiveServerTestCase):

    IDENTITY = 'test'
    PASS = 'test'
    WALLET_UID = 'test_wallet_uid'
    WALLET_PASS_PHRASE = 'pass'
    DEF_TIMEOUT = 5

    def setUp(self):
        self.account = AgentAccount.objects.create(username=self.IDENTITY, is_active=True, is_staff=True)
        self.account.set_password(self.PASS)
        self.account.save()
        self.assertTrue(self.account.check_password(self.PASS))
        with connection.cursor() as cursor:
            cursor.execute("DROP DATABASE  IF EXISTS %s" % self.WALLET_UID)

    def test_list(self):
        url = self.live_server_url + reverse('admin-wallets-list')
        endpoint1 = Endpoint.objects.create(uid='uid1', owner=self.account)
        endpoint2 = Endpoint.objects.create(uid='uid2', owner=self.account)
        wallet1 = Wallet.objects.create(uid='wallet-1', endpoint=endpoint1, owner=self.account)
        wallet2 = Wallet.objects.create(uid='wallet-2', endpoint=endpoint2, owner=self.account)
        wallet3 = Wallet.objects.create(uid='wallet-3', endpoint=None, owner=None)
        resp = requests.get(url, auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
        self.assertEqual(200, resp.status_code)
        results = resp.json()
        self.assertIn(endpoint1.uid, str(results))
        self.assertIn(endpoint2.uid, str(results))
        self.assertIn(wallet1.uid, str(results))
        self.assertIn(wallet2.uid, str(results))
        self.assertNotIn(wallet3.uid, str(results))

    def test_retrieve(self):
        endpoint = Endpoint.objects.create(uid='endpoint-uid', owner=self.account)
        wallet = Wallet.objects.create(uid='wallet-uid', endpoint=endpoint, owner=self.account)
        url = self.live_server_url + reverse('admin-wallets-detail', kwargs=dict(uid=wallet.uid))
        resp = requests.get(url, auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
        self.assertEqual(200, resp.status_code)
        results = resp.json()
        self.assertIn(wallet.uid, str(results))
        self.assertIn(endpoint.uid, str(results))
