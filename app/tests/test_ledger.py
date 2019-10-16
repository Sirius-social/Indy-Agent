import os
import uuid
import json
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


class LedgerTest(LiveServerTestCase):

    IDENTITY1 = 'test1'
    IDENTITY2 = 'test2'
    PASS = 'test'
    WALLET1_UID = 'test_wallet_uid_1'
    WALLET2_UID = 'test_wallet_uid_2'
    WALLET_PASS_PHRASE = 'pass'
    WALLET1_DB_NAME = WalletConnection.make_wallet_address(WALLET1_UID)
    WALLET2_DB_NAME = WalletConnection.make_wallet_address(WALLET2_UID)
    DEF_TIMEOUT = 5

    def setUp(self):
        self.account1 = AgentAccount.objects.create(username=self.IDENTITY1, is_active=True, is_staff=True)
        self.account1.set_password(self.PASS)
        self.account1.save()
        self.account2 = AgentAccount.objects.create(username=self.IDENTITY2, is_active=True, is_staff=True)
        self.account2.set_password(self.PASS)
        self.account2.save()
        os.popen("pkill -f run_wallet_agent")
        sleep(0.1)
        psax = get_ps_ax()
        self.assertNotIn('run_wallet_agent', psax, psax)
        with connection.cursor() as cursor:
            cursor.execute("DROP DATABASE  IF EXISTS %s" % self.WALLET1_DB_NAME)
            cursor.execute("DROP DATABASE  IF EXISTS %s" % self.WALLET2_DB_NAME)

    def create_and_open_wallet(self, wallet_uid: str, account: str):
        # create
        cred = dict(uid=wallet_uid, pass_phrase=self.WALLET_PASS_PHRASE)
        url = self.live_server_url + reverse('admin-wallets-list')
        resp = requests.post(url, json=cred, auth=HTTPBasicAuth(account, self.PASS))
        self.assertEqual(201, resp.status_code)
        # open
        cred = dict(pass_phrase=self.WALLET_PASS_PHRASE)
        url = self.live_server_url + reverse('admin-wallets-open', kwargs=dict(uid=wallet_uid))
        resp = requests.post(url, json=cred, auth=HTTPBasicAuth(account, self.PASS))
        self.assertEqual(200, resp.status_code)
        url = self.live_server_url + reverse('admin-wallets-is-open', kwargs=dict(uid=wallet_uid))
        resp = requests.get(url, auth=HTTPBasicAuth(account, self.PASS))
        self.assertEqual(200, resp.status_code)

    def close_and_delete_wallet(self, wallet_uid: str, account: str):
        cred = dict(pass_phrase=self.WALLET_PASS_PHRASE)
        # close
        url = self.live_server_url + reverse('admin-wallets-close', kwargs=dict(uid=wallet_uid))
        resp = requests.post(url, json=cred, auth=HTTPBasicAuth(account, self.PASS))
        self.assertEqual(200, resp.status_code)
        # destroy
        url = self.live_server_url + reverse('admin-wallets-detail', kwargs=dict(uid=wallet_uid))
        resp = requests.delete(url, json=cred, auth=HTTPBasicAuth(account, self.PASS))
        self.assertEqual(204, resp.status_code)

    def ensure_did_exists(self, account: str, wallet_uid: str, seed: str):
        url = self.live_server_url + '/agent/admin/wallets/%s/did/create_and_store_my_did/' % wallet_uid
        cred = dict(pass_phrase=self.WALLET_PASS_PHRASE, seed=seed)
        resp = requests.post(url, json=cred, auth=HTTPBasicAuth(account, self.PASS))
        self.assertEqual(201, resp.status_code)
        info = resp.json()
        return info['did'], info['verkey']

    def create_did(self, account: str, wallet_uid: str):
        url = self.live_server_url + '/agent/admin/wallets/%s/did/create_and_store_my_did/' % wallet_uid
        cred = dict(pass_phrase=self.WALLET_PASS_PHRASE)
        resp = requests.post(url, json=cred, auth=HTTPBasicAuth(account, self.PASS))
        self.assertEqual(201, resp.status_code)
        info = resp.json()
        return info['did'], info['verkey']

    def test_send_nym_request(self):
        account_steward = self.IDENTITY1
        account_trustee = self.IDENTITY2
        wallet_steward = self.WALLET1_UID
        wallet_trustee = self.WALLET2_UID
        self.create_and_open_wallet(wallet_steward, account_steward)
        self.create_and_open_wallet(wallet_trustee, account_trustee)
        try:
            did_steward, verkey_steward = self.ensure_did_exists(account_steward, wallet_steward, '000000000000000000000000Steward1')
            did_trustee, verkey_trustee = self.create_did(account_trustee, wallet_trustee)

            url = self.live_server_url + '/agent/admin/wallets/%s/did/%s/ledger/nym_request/' % (wallet_steward, did_steward)
            entity = dict(target_did=did_trustee, ver_key=verkey_trustee, role='TRUST_ANCHOR', pass_phrase=self.WALLET_PASS_PHRASE)
            resp = requests.post(url, json=entity, auth=HTTPBasicAuth(account_steward, self.PASS))
            self.assertEqual(200, resp.status_code)
            self.assertTrue(resp.json())

            resp = requests.post(url, json=entity, auth=HTTPBasicAuth(account_steward, self.PASS))
            self.assertEqual(400, resp.status_code)
            self.assertIn('STEWARD can not touch role field since only the owner can modify', resp.text)
        finally:
            self.close_and_delete_wallet(wallet_steward, account_steward)
            self.close_and_delete_wallet(wallet_trustee, account_trustee)

    def test_register_schema(self):
        account_steward = self.IDENTITY1
        wallet_steward = self.WALLET1_UID
        self.create_and_open_wallet(wallet_steward, account_steward)
        try:
            did_steward, verkey_steward = self.ensure_did_exists(account_steward, wallet_steward, '000000000000000000000000Steward1')
            schema = {
                'pass_phrase': self.WALLET_PASS_PHRASE,
                'name': 'test_schema_' + uuid.uuid4().hex,
                'version': '1.0',
                'attributes': ["age", "sex", "height", "name"]
            }
            url = self.live_server_url + '/agent/admin/wallets/%s/did/%s/ledger/register_schema/' % (wallet_steward, did_steward)
            resp = requests.post(url, json=schema, auth=HTTPBasicAuth(account_steward, self.PASS))
            self.assertEqual(201, resp.status_code)
            self.assertTrue(resp.json())
            schema_json = json.dumps(resp.json()['schema'])

            resp = requests.post(url, json=schema, auth=HTTPBasicAuth(account_steward, self.PASS))
            self.assertEqual(409, resp.status_code)

            # query schemas
            url = self.live_server_url + '/agent/admin/wallets/%s/did/%s/ledger/schemas/' % (wallet_steward, did_steward)
            resp = requests.get(url, auth=HTTPBasicAuth(account_steward, self.PASS))
            raw = json.dumps(resp.json())
            self.assertIn(schema_json, raw)
        finally:
            self.close_and_delete_wallet(wallet_steward, account_steward)

    def test_create_and_store_credential_def(self):
        account_issuer = self.IDENTITY1
        wallet_issuer = self.WALLET1_UID
        self.create_and_open_wallet(wallet_issuer, account_issuer)
        try:
            did_steward, verkey_steward = self.ensure_did_exists(account_issuer, wallet_issuer, '000000000000000000000000Steward1')
            schema = {
                'pass_phrase': self.WALLET_PASS_PHRASE,
                'name': 'test_schema_' + uuid.uuid4().hex,
                'version': '1.0',
                'attributes': ["age", "sex", "height", "name"]
            }
            url = self.live_server_url + '/agent/admin/wallets/%s/did/%s/ledger/register_schema/' % (wallet_issuer, did_steward)
            resp = requests.post(url, json=schema, auth=HTTPBasicAuth(account_issuer, self.PASS))
            self.assertEqual(201, resp.status_code)
            self.assertTrue(resp.json())
            schema_json = resp.json()['schema']

            did_trustee, verkey_trustee = self.create_did(account_issuer, wallet_issuer)
            url = self.live_server_url + '/agent/admin/wallets/%s/did/%s/cred_def/create_and_store/' % (wallet_issuer, did_trustee)
            cred_def = {
                'pass_phrase': self.WALLET_PASS_PHRASE,
                'schema': schema_json,
                'tag': 'TAG1',
                'support_revocation': False
            }
            resp = requests.post(url, json=cred_def, auth=HTTPBasicAuth(account_issuer, self.PASS))
            self.assertEqual(201, resp.status_code)
            self.assertTrue(resp.json().get('id'))
            self.assertTrue(resp.json().get('cred_def'))

            resp = requests.post(url, json=cred_def, auth=HTTPBasicAuth(account_issuer, self.PASS))
            self.assertEqual(409, resp.status_code)

            # check cred_def_list
            url = self.live_server_url + '/agent/admin/wallets/%s/did/%s/cred_def/all/' % (wallet_issuer, did_trustee)
            resp = requests.get(url, auth=HTTPBasicAuth(account_issuer, self.PASS))
            raw = json.dumps(resp.json())
            self.assertIn(schema['name'], raw)
        finally:
            self.close_and_delete_wallet(wallet_issuer, account_issuer)
