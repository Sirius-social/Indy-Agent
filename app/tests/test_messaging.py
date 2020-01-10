import os
import uuid
import json
import threading
from time import sleep

import requests
from requests.auth import HTTPBasicAuth
from django.test import LiveServerTestCase
from django.urls import reverse
from django.db import connection

from authentication.models import AgentAccount
from core.wallet import WalletConnection
from transport.models import Endpoint
from core.utils import HEADER_PASS_PHRASE
from core.sync2async import run_async
from core.base import EndpointTransport


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
        # create endpoint
        endpoint_uid = 'endpoint_for_' + wallet_uid
        account_inst = AgentAccount.objects.get(username=account)
        endpoint = Endpoint.objects.create(
            uid=endpoint_uid, owner=account_inst, wallet=account_inst.wallets.first(),
            url=reverse('endpoint', kwargs=dict(uid=endpoint_uid))
        )
        return self.live_server_url + endpoint.url

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

    @staticmethod
    def ws_read_json(ws, timeout=5):

        ret = None
        ev = threading.Event()

        def routine(ws):
            nonlocal ret
            ret = json.loads(ws.recv())
            ev.set()

        th = threading.Thread(target=routine, args=(ws,))
        th.daemon = True
        th.start()
        if ev.wait(timeout):
            return ret
        else:
            raise TimeoutError()

    def test_anon_crypt_message(self):
        account_sender = self.IDENTITY1
        account_receiver = self.IDENTITY2
        wallet_sender = self.WALLET1_UID
        wallet_receiver = self.WALLET2_UID
        self.create_and_open_wallet(wallet_sender, account_sender)
        self.create_and_open_wallet(wallet_receiver, account_receiver)
        try:
            did_sender, verkey_sender = self.create_did(account_sender, wallet_sender)
            did_receiver, verkey_receiver = self.create_did(account_receiver, wallet_receiver)
            url = self.live_server_url + '/agent/admin/wallets/%s/messaging/anon_crypt/' % wallet_sender
            # Message
            message = dict(content=uuid.uuid4().hex)
            # Encrypt
            entity = dict(
                message=message,
                their_verkey=verkey_receiver
            )
            resp = requests.post(url, json=entity, auth=HTTPBasicAuth(account_sender, self.PASS))
            self.assertEqual(200, resp.status_code)
            encrypted = resp.json()
            print('-------- Encrypted --------')
            print(json.dumps(encrypted, indent=2, sort_keys=True))
            self.assertNotIn(message['content'], str(encrypted))
            # Decrypt
            url = self.live_server_url + '/agent/admin/wallets/%s/messaging/unpack/' % wallet_receiver
            resp = requests.post(
                url,
                json=encrypted,
                auth=HTTPBasicAuth(account_receiver, self.PASS)
            )
            self.assertEqual(200, resp.status_code, resp.text)
            decrypted = resp.json()
            print('--------- Decrypted -------')
            print(json.dumps(decrypted, indent=2, sort_keys=True))
            self.assertIn(message['content'], str(decrypted))
        finally:
            self.close_and_delete_wallet(wallet_sender, account_sender)
            self.close_and_delete_wallet(wallet_receiver, account_receiver)

    def test_auth_crypt_message(self):
        account_sender = self.IDENTITY1
        account_receiver = self.IDENTITY2
        wallet_sender = self.WALLET1_UID
        wallet_receiver = self.WALLET2_UID
        self.create_and_open_wallet(wallet_sender, account_sender)
        self.create_and_open_wallet(wallet_receiver, account_receiver)
        try:
            did_sender, verkey_sender = self.create_did(account_sender, wallet_sender)
            did_receiver, verkey_receiver = self.create_did(account_receiver, wallet_receiver)
            url = self.live_server_url + '/agent/admin/wallets/%s/messaging/auth_crypt/' % wallet_sender
            # Message
            message = dict(content=uuid.uuid4().hex)
            # Encrypt
            entity = dict(
                message=message,
                their_verkey=verkey_receiver,
                my_verkey=verkey_sender
            )
            resp = requests.post(url, json=entity, auth=HTTPBasicAuth(account_sender, self.PASS))
            self.assertEqual(200, resp.status_code)
            encrypted = resp.json()
            print('-------- Encrypted --------')
            print(json.dumps(encrypted, indent=2, sort_keys=True))
            self.assertNotIn(message['content'], str(encrypted))
            # Decrypt
            url = self.live_server_url + '/agent/admin/wallets/%s/messaging/unpack/' % wallet_receiver
            resp = requests.post(
                url,
                json=encrypted,
                auth=HTTPBasicAuth(account_receiver, self.PASS)
            )
            self.assertEqual(200, resp.status_code, resp.text)
            decrypted = resp.json()
            print('--------- Decrypted -------')
            print(json.dumps(decrypted, indent=2, sort_keys=True))
            self.assertIn(message['content'], str(decrypted))
        finally:
            self.close_and_delete_wallet(wallet_sender, account_sender)
            self.close_and_delete_wallet(wallet_receiver, account_receiver)

    def test_receive_wired_message(self):
        headers = dict()
        headers[HEADER_PASS_PHRASE] = self.WALLET_PASS_PHRASE
        account_sender = self.IDENTITY1
        account_receiver = self.IDENTITY2
        wallet_sender = self.WALLET1_UID
        wallet_receiver = self.WALLET2_UID
        endpoint_sender = self.create_and_open_wallet(wallet_sender, account_sender)
        endpoint_receiver = self.create_and_open_wallet(wallet_receiver, account_receiver)
        try:
            did_sender, verkey_sender = self.create_did(account_sender, wallet_sender)
            did_receiver, verkey_receiver = self.create_did(account_receiver, wallet_receiver)
            # create pairwise on receiver-side
            url = self.live_server_url + '/agent/admin/wallets/%s/pairwise/create_pairwise_statically/' % wallet_receiver
            pairwise = dict(
                my_did=did_receiver,
                their_did=did_sender,
                their_verkey=verkey_sender,
                metadata={
                    'their_endpoint': endpoint_sender,
                    'their_vk': verkey_sender,
                    'my_vk': verkey_receiver,
                }
            )
            resp = requests.post(url, json=pairwise, auth=HTTPBasicAuth(account_receiver, self.PASS), headers=headers)
            self.assertEqual(200, resp.status_code, resp.text)
            # create auth-crypt message
            url = self.live_server_url + '/agent/admin/wallets/%s/messaging/auth_crypt/' % wallet_sender
            message = dict(content=uuid.uuid4().hex)
            entity = dict(
                message=message,
                their_verkey=verkey_receiver,
                my_verkey=verkey_sender
            )
            resp = requests.post(url, json=entity, auth=HTTPBasicAuth(account_sender, self.PASS))
            self.assertEqual(200, resp.status_code)
            encrypted_message = resp.json()
            # send to receiver endpoint
            transport = EndpointTransport(address=endpoint_receiver)
            status = run_async(transport.send_wire_message(encrypted_message))
            self.assertEqual(410, status)
        finally:
            self.close_and_delete_wallet(wallet_sender, account_sender)
            self.close_and_delete_wallet(wallet_receiver, account_receiver)
