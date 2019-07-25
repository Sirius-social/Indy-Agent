import os
from time import sleep

import requests
from requests.auth import HTTPBasicAuth
from django.test import LiveServerTestCase
from django.urls import reverse
from django.db import connection

from authentication.models import AgentAccount
from api.models import Wallet
from api.sync2async import run_async
from transport.models import Endpoint
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
        self.assertTrue(w['endpoint'])
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

    def test_generate_invite_link(self):
        conn = WalletConnection(self.WALLET_UID, self.WALLET_PASS_PHRASE)
        e = Endpoint.objects.create(uid='endpoint_uid', owner=self.account)
        Wallet.objects.create(uid=self.WALLET_UID, owner=self.account, endpoint=e)
        # first: create wallet
        run_async(conn.create())
        try:
            cred = dict(pass_phrase=self.WALLET_PASS_PHRASE)
            url = self.live_server_url + reverse('admin-wallets-generate-invite-link', kwargs=dict(uid=self.WALLET_UID))
            resp = requests.post(url, json=cred, auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
            self.assertEqual(200, resp.status_code)
            entity = resp.json()
            self.assertTrue(entity['invite_link'])
        finally:
            os.popen("pkill -f run_wallet_agent")
            sleep(1)
            run_async(conn.delete())
