import os
import re
import json
import base64
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
from core.utils import HEADER_PASS_PHRASE
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

    def test_open_close__via_http_header(self):
        conn = WalletConnection(self.WALLET_UID, self.WALLET_PASS_PHRASE)
        Wallet.objects.create(uid=self.WALLET_UID, owner=self.account)
        # first: create wallet
        run_async(conn.create())
        headers = dict()
        headers[HEADER_PASS_PHRASE] = self.WALLET_PASS_PHRASE
        try:
            # open
            url = self.live_server_url + reverse('admin-wallets-open', kwargs=dict(uid=self.WALLET_UID))
            resp = requests.post(url, auth=HTTPBasicAuth(self.IDENTITY, self.PASS), headers=headers)
            self.assertEqual(200, resp.status_code)
            # is_open
            url = self.live_server_url + reverse('admin-wallets-is-open', kwargs=dict(uid=self.WALLET_UID))
            resp = requests.get(url, auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
            self.assertEqual(200, resp.status_code)
            stat = resp.json()
            self.assertTrue(stat['is_open'])
            # close
            url = self.live_server_url + reverse('admin-wallets-close', kwargs=dict(uid=self.WALLET_UID))
            resp = requests.post(url, auth=HTTPBasicAuth(self.IDENTITY, self.PASS), headers=headers)
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
        endpoint_path = reverse('endpoint', kwargs=dict(uid=endpoint_uid))
        self.assertIn(endpoint_path, resp.json()['url'])
        # step 2: list endpoints
        resp = requests.get(base_url, auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
        self.assertEqual(200, resp.status_code)
        self.assertIn(endpoint_uid, str(resp.json()))
        # step 3: destroy
        self.assertTrue(Endpoint.objects.filter(uid=endpoint_uid).exists())
        resp = requests.delete(base_url + endpoint_uid + '/', auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
        self.assertEqual(204, resp.status_code)
        self.assertFalse(Endpoint.objects.filter(uid=endpoint_uid).exists())

    def test_create_endpoint_with_custom_host(self):
        wallet = Wallet.objects.create(uid='wallet_uid', owner=self.account)
        base_url = self.live_server_url + '/agent/admin/wallets/%s/endpoints/' % wallet.uid
        custom_host = 'http://example.com:8888/'
        resp = requests.post(base_url, json=dict(host=custom_host), auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
        data = resp.json()
        self.assertIn(custom_host, data['url'])

    def test_create_invitation(self):
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
            self.assertTrue(resp.json()['connection_key'])
            connection_key = resp.json()['connection_key']
            self.assertIn(instance.invitation_string, invite_url)
            self.assertIn(settings.INDY['INVITATION_URL_BASE'], invite_url)
            self.assertEqual(1, invite_url.count('c_i='))
            # check list
            resp = requests.get(url, auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
            self.assertEqual(200, resp.status_code)
            raw = str(resp.json())
            self.assertIn(invite_url, raw)
            self.assertIn(connection_key, raw)
        finally:
            os.popen("pkill -f run_wallet_agent")
            sleep(1)
            run_async(conn.delete())

    def test_create_invitation__with_label(self):
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
            label = 'My Test Label'
            cred = dict(pass_phrase=self.WALLET_PASS_PHRASE, label=label)
            url = self.live_server_url + '/agent/admin/wallets/%s/endpoints/%s/invitations/' % (
            self.WALLET_UID, endpoint.uid)
            resp = requests.post(url, json=cred, auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
            self.assertEqual(201, resp.status_code)
            entity = resp.json()
            self.assertTrue(entity['url'])
            invite_url = entity['url']
            matches = re.match("(.+)?c_i=(.+)", invite_url)
            self.assertTrue(matches)
            _ = base64.urlsafe_b64decode(matches.group(2)).decode('utf-8')
            invite_msg = json.loads(_)
            self.assertEqual(label, invite_msg.get('label'))
        finally:
            os.popen("pkill -f run_wallet_agent")
            sleep(1)
            run_async(conn.delete())

    def test_ensure_exists(self):
        conn = WalletConnection(self.WALLET_UID, self.WALLET_PASS_PHRASE)
        try:
            url = self.live_server_url + '/agent/admin/wallets/ensure_exists/'
            cred = dict(pass_phrase=self.WALLET_PASS_PHRASE, uid=self.WALLET_UID)
            resp = requests.post(url, json=cred, auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
            self.assertIn(resp.status_code, [200, 201])
        finally:
            os.popen("pkill -f run_wallet_agent")
            sleep(1)
            run_async(conn.delete())

    def test_list_my_dids_with_meta(self):
        conn = WalletConnection(self.WALLET_UID, self.WALLET_PASS_PHRASE)
        wallet = Wallet.objects.create(uid=self.WALLET_UID, owner=self.account)
        url = self.live_server_url + '/agent/admin/wallets/%s/did/list_my_dids_with_meta/' % wallet.uid
        # first: create wallet
        run_async(conn.create())
        try:
            # create did from seed
            run_async(conn.open())
            did, verkey = run_async(conn.create_and_store_my_did(seed='000000000000000000000000Steward1'))
            run_async(conn.close())
            cred = dict(pass_phrase=self.WALLET_PASS_PHRASE)
            # open
            url_open = self.live_server_url + reverse('admin-wallets-open', kwargs=dict(uid=self.WALLET_UID))
            resp = requests.post(url_open, json=cred, auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
            self.assertEqual(200, resp.status_code)
            # FIRE!!!
            resp = requests.post(url, json=cred, auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
            self.assertEqual(200, resp.status_code)
            raw = json.dumps(resp.json())
            self.assertIn(did, raw)
            self.assertIn(verkey, raw)
        finally:
            os.popen("pkill -f run_wallet_agent")
            sleep(1)
            run_async(conn.delete())

    def test_create_and_store_my_did__with_seed(self):
        conn = WalletConnection(self.WALLET_UID, self.WALLET_PASS_PHRASE)
        wallet = Wallet.objects.create(uid=self.WALLET_UID, owner=self.account)
        url = self.live_server_url + '/agent/admin/wallets/%s/did/create_and_store_my_did/' % wallet.uid
        # first: create wallet
        run_async(conn.create())
        try:
            cred = dict(pass_phrase=self.WALLET_PASS_PHRASE, seed='000000000000000000000000Steward1')
            # open
            url_open = self.live_server_url + reverse('admin-wallets-open', kwargs=dict(uid=self.WALLET_UID))
            resp = requests.post(url_open, json=cred, auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
            self.assertEqual(200, resp.status_code)
            # FIRE!!!
            resp = requests.post(url, json=cred, auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
            self.assertEqual(201, resp.status_code)
            info = resp.json()
            self.assertTrue(info.get('did'))
            self.assertTrue(info.get('verkey'))
            # Fire second time
            resp = requests.post(url, json=cred, auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
            self.assertIn(resp.status_code, [201, 409])
        finally:
            os.popen("pkill -f run_wallet_agent")
            sleep(1)
            run_async(conn.delete())

    def test_create_and_store_my_did__without_seed(self):
        conn = WalletConnection(self.WALLET_UID, self.WALLET_PASS_PHRASE)
        wallet = Wallet.objects.create(uid=self.WALLET_UID, owner=self.account)
        url = self.live_server_url + '/agent/admin/wallets/%s/did/create_and_store_my_did/' % wallet.uid
        # first: create wallet
        run_async(conn.create())
        try:
            cred = dict(pass_phrase=self.WALLET_PASS_PHRASE)
            # open
            url_open = self.live_server_url + reverse('admin-wallets-open', kwargs=dict(uid=self.WALLET_UID))
            resp = requests.post(url_open, json=cred, auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
            self.assertEqual(200, resp.status_code)
            # FIRE!!!
            resp = requests.post(url, json=cred, auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
            self.assertEqual(201, resp.status_code)
            info1 = resp.json()
            self.assertTrue(info1.get('did'))
            self.assertTrue(info1.get('verkey'))
            # Fire second time
            resp = requests.post(url, json=cred, auth=HTTPBasicAuth(self.IDENTITY, self.PASS))
            self.assertEqual(201, resp.status_code)
            info2 = resp.json()
            self.assertTrue(info2.get('did'))
            self.assertTrue(info2.get('verkey'))
            # compare both answers
            self.assertNotEqual(info1['did'], info2['did'])
            self.assertNotEqual(info1['verkey'], info2['verkey'])
        finally:
            os.popen("pkill -f run_wallet_agent")
            sleep(1)
            run_async(conn.delete())