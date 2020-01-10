import os
import uuid
import json
from time import sleep

import requests
from requests.auth import HTTPBasicAuth
from django.test import LiveServerTestCase
from django.urls import reverse
from django.db import connection

from authentication.models import AgentAccount
from core.wallet import WalletConnection
from core.utils import HEADER_PASS_PHRASE


def get_ps_ax():
    pipe = os.popen('ps ax')
    output = pipe.read()
    return output


class MessagingTest(LiveServerTestCase):

    IDENTITY1 = 'test1'
    IDENTITY2 = 'test2'
    IDENTITY3 = 'test3'
    PASS = 'test'
    WALLET1_UID = 'test_wallet_uid_1'
    WALLET2_UID = 'test_wallet_uid_2'
    WALLET3_UID = 'test_wallet_uid_3'
    WALLET_PASS_PHRASE = 'pass'
    WALLET1_DB_NAME = WalletConnection.make_wallet_address(WALLET1_UID)
    WALLET2_DB_NAME = WalletConnection.make_wallet_address(WALLET2_UID)
    WALLET3_DB_NAME = WalletConnection.make_wallet_address(WALLET3_UID)
    DEF_TIMEOUT = 5

    def setUp(self):
        self.account1 = AgentAccount.objects.create(username=self.IDENTITY1, is_active=True, is_staff=True)
        self.account1.set_password(self.PASS)
        self.account1.save()
        self.account2 = AgentAccount.objects.create(username=self.IDENTITY2, is_active=True, is_staff=True)
        self.account2.set_password(self.PASS)
        self.account2.save()
        self.account3 = AgentAccount.objects.create(username=self.IDENTITY3, is_active=True, is_staff=True)
        self.account3.set_password(self.PASS)
        self.account3.save()
        os.popen("pkill -f run_wallet_agent")
        sleep(0.1)
        psax = get_ps_ax()
        self.assertNotIn('run_wallet_agent', psax, psax)
        with connection.cursor() as cursor:
            cursor.execute("DROP DATABASE  IF EXISTS %s" % self.WALLET1_DB_NAME)
            cursor.execute("DROP DATABASE  IF EXISTS %s" % self.WALLET2_DB_NAME)
            cursor.execute("DROP DATABASE  IF EXISTS %s" % self.WALLET3_DB_NAME)

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

    def test_create_pairwise_statically(self):
        headers = dict()
        headers[HEADER_PASS_PHRASE] = self.WALLET_PASS_PHRASE
        account_1 = self.IDENTITY1
        account_2 = self.IDENTITY2
        wallet_1 = self.WALLET1_UID
        wallet_2 = self.WALLET2_UID
        self.create_and_open_wallet(wallet_1, account_1)
        self.create_and_open_wallet(wallet_2, account_2)
        try:
            did_1, verkey_1 = self.create_did(account_1, wallet_1)
            did_2, verkey_2 = self.create_did(account_2, wallet_2)
            url = self.live_server_url + '/agent/admin/wallets/%s/pairwise/create_pairwise/' % wallet_1
            #
            pairwise = dict(
                my_did=did_1,
                their_did=did_2,
                their_verkey=verkey_2,
                metadata=dict(
                    x=1,
                    y=2,
                    z='123'
                )
            )
            resp = requests.post(url, json=pairwise, auth=HTTPBasicAuth(account_1, self.PASS), headers=headers)
            self.assertEqual(200, resp.status_code, resp.text)
            url = self.live_server_url + '/agent/admin/wallets/%s/pairwise/all/' % wallet_1
            resp = requests.post(url, auth=HTTPBasicAuth(account_1, self.PASS), headers=headers)
            self.assertEqual(200, resp.status_code)
            ret = resp.json()
            self.assertEqual(1, len(ret))
            actual = ret[0]
            self.assertEqual(actual['my_did'], pairwise['my_did'])
            self.assertEqual(actual['their_did'], pairwise['their_did'])
            self.assertEqual(actual['metadata'], pairwise['metadata'])
        finally:
            self.close_and_delete_wallet(wallet_1, account_1)
            self.close_and_delete_wallet(wallet_2, account_2)
