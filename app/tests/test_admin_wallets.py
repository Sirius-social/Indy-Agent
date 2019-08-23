import os
from time import sleep

import requests
from requests.auth import HTTPBasicAuth
from django.test import LiveServerTestCase
from django.urls import reverse
from django.conf import settings
from django.db import connection

from authentication.models import AgentAccount
from api.models import Wallet
from core.sync2async import run_async
from transport.models import Endpoint, Invitation
from core.wallet import WalletConnection


def get_ps_ax():
    pipe = os.popen('ps ax')
    output = pipe.read()
    return output


class AdminWalletsTest(LiveServerTestCase):

    IDENTITY = 'test'
    PASS = 'test'
    WALLET_UID = 'test_wallet_uid'
    WALLET_PASS_PHRASE = 'pass'
    WALLET_DB_NAME = WalletConnection.make_wallet_address(WALLET_UID)
    DEF_TIMEOUT = 5

    def setUp(self):
        self.account = AgentAccount.objects.create(username=self.IDENTITY, is_active=True, is_staff=True)
        self.account.set_password(self.PASS)
        self.account.save()
        self.assertTrue(self.account.check_password(self.PASS))
        os.popen("pkill -f run_wallet_agent")
        sleep(0.1)
        psax = get_ps_ax()
        self.assertNotIn('run_wallet_agent', psax, psax)
        with connection.cursor() as cursor:
            cursor.execute("DROP DATABASE  IF EXISTS %s" % self.WALLET_DB_NAME)

    def test_list(self):
        url = self.live_server_url + reverse('admin-wallets-list')
        wallet1 = Wallet.objects.create(uid='wallet-1', owner=self.account)
        wallet2 = Wallet.objects.create(uid='wallet-2', owner=self.account)
        wallet3 = Wallet.objects.create(uid='wallet-3', owner=None)
        resp = requests.get(url, auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
        self.assertEqual(200, resp.status_code)
        results = resp.json()
        self.assertIn(wallet1.uid, str(results))
        self.assertIn(wallet2.uid, str(results))
        self.assertNotIn(wallet3.uid, str(results))

    def test_retrieve(self):
        wallet = Wallet.objects.create(uid='wallet-uid', owner=self.account)
        url = self.live_server_url + reverse('admin-wallets-detail', kwargs=dict(uid=wallet.uid))
        resp = requests.get(url, auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
        self.assertEqual(200, resp.status_code)
        results = resp.json()
        self.assertIn(wallet.uid, str(results))

    def test_create_destroy(self):
        url = self.live_server_url + reverse('admin-wallets-list')
        cred = dict(uid=self.WALLET_UID, pass_phrase=self.WALLET_PASS_PHRASE)
        resp = requests.post(url, json=cred, auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
        self.assertEqual(201, resp.status_code)
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM pg_database WHERE datname='%s'" % self.WALLET_DB_NAME)
            res = cursor.fetchone()
            self.assertTrue(res)
            self.assertEqual(1, res[0])
        w = resp.json()
        self.assertTrue(w['uid'])
        url = self.live_server_url + reverse('admin-wallets-detail', kwargs=dict(uid=w['uid']))
        resp = requests.delete(url, json=cred, auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
        self.assertEqual(204, resp.status_code)
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM pg_database WHERE datname='%s'" % self.WALLET_DB_NAME)
            res = cursor.fetchone()
            self.assertFalse(res)

    def test_open_close(self):
        conn = WalletConnection(self.WALLET_UID, self.WALLET_PASS_PHRASE)
        Wallet.objects.create(uid=self.WALLET_UID, owner=self.account)
        # first: create wallet
        run_async(conn.create())
        try:
            cred = dict(pass_phrase=self.WALLET_PASS_PHRASE)
            # open
            url = self.live_server_url + reverse('admin-wallets-open', kwargs=dict(uid=self.WALLET_UID))
            resp = requests.post(url, json=cred, auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
            self.assertEqual(200, resp.status_code)
            # is_open
            url = self.live_server_url + reverse('admin-wallets-is-open', kwargs=dict(uid=self.WALLET_UID))
            resp = requests.get(url, auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
            self.assertEqual(200, resp.status_code)
            stat = resp.json()
            self.assertTrue(stat['is_open'])
            # close
            url = self.live_server_url + reverse('admin-wallets-close', kwargs=dict(uid=self.WALLET_UID))
            resp = requests.post(url, json=cred, auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
            self.assertEqual(200, resp.status_code)
            # is_open
            url = self.live_server_url + reverse('admin-wallets-is-open', kwargs=dict(uid=self.WALLET_UID))
            resp = requests.get(url, auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
            self.assertEqual(200, resp.status_code)
            stat = resp.json()
            self.assertFalse(stat['is_open'])
        finally:
            os.popen("pkill -f run_wallet_agent")
            sleep(1)
            run_async(conn.delete())

    def test_create_list_destroy_endpoints(self):
        wallet = Wallet.objects.create(uid='wallet_uid', owner=self.account)
        base_url = self.live_server_url + '/agent/admin/wallets/%s/endpoints/' % wallet.uid
        # step 1: create endpoint
        resp = requests.post(base_url, auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
        self.assertEqual(201, resp.status_code)
        self.assertTrue(resp.json()['url'])
        self.assertTrue(resp.json()['uid'])
        endpoint_uid = resp.json()['uid']
        # step 2: list endpoints
        resp = requests.get(base_url, auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
        self.assertEqual(200, resp.status_code)
        self.assertIn(endpoint_uid, str(resp.json()))
        # step 3: destroy
        self.assertTrue(Endpoint.objects.filter(uid=endpoint_uid).exists())
        resp = requests.delete(base_url + endpoint_uid + '/', auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
        self.assertEqual(204, resp.status_code)
        self.assertFalse(Endpoint.objects.filter(uid=endpoint_uid).exists())

    def test_create_invite_link(self):
        conn = WalletConnection(self.WALLET_UID, self.WALLET_PASS_PHRASE)
        wallet = Wallet.objects.create(uid=self.WALLET_UID, owner=self.account)
        endpoint = Endpoint.objects.create(
            uid='endpoint_uid',
            owner=self.account,
            wallet=wallet,
            url='http://example.com/endpoint'
        )
        # first: create wallet
        run_async(conn.create())
        try:
            cred = dict(pass_phrase=self.WALLET_PASS_PHRASE)
            url = self.live_server_url + '/agent/admin/wallets/%s/endpoints/%s/invitations/' % (self.WALLET_UID, endpoint.uid)
            resp = requests.post(url, json=cred, auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
            self.assertEqual(201, resp.status_code)
            instance = Invitation.objects.get(endpoint=endpoint)
            entity = resp.json()
            self.assertTrue(entity['url'])
            invite_url = entity['url']
            self.assertIn(instance.invitation_string, invite_url)
            self.assertIn(settings.INDY['INVITATION_URL_BASE'], invite_url)
            self.assertEqual(1, invite_url.count('c_i='))
            # check list
            resp = requests.get(url, auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
            self.assertEqual(200, resp.status_code)
            raw = str(resp.json())
            self.assertIn(invite_url, raw)
        finally:
            os.popen("pkill -f run_wallet_agent")
            sleep(1)
            run_async(conn.delete())
