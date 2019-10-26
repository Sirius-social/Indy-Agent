import os
import uuid
import json
from time import sleep
from unittest import skip

import requests
from requests.auth import HTTPBasicAuth
from django.test import LiveServerTestCase
from django.urls import reverse
from django.db import connection

from authentication.models import AgentAccount
from core.wallet import WalletConnection


def get_ps_ax():
    pipe = os.popen('ps ax')
    output = pipe.read()
    return output


class LedgerTest(LiveServerTestCase):

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

            # retrieve
            url = self.live_server_url + '/agent/admin/wallets/%s/did/%s/ledger/retrieve_did/' % (wallet_steward, did_steward)
            get_nym = dict(did=did_trustee, pass_phrase=self.WALLET_PASS_PHRASE)
            resp = requests.post(url, json=get_nym, auth=HTTPBasicAuth(account_steward, self.PASS))
            self.assertEqual(200, resp.status_code, resp.text)
            self.assertTrue(resp.json())
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
            schema_id = resp.json()['schema']['id']

            resp = requests.post(url, json=schema, auth=HTTPBasicAuth(account_steward, self.PASS))
            self.assertEqual(409, resp.status_code)

            # query schemas
            url = self.live_server_url + '/agent/admin/wallets/%s/did/%s/ledger/schemas/' % (wallet_steward, did_steward)
            resp = requests.get(url, auth=HTTPBasicAuth(account_steward, self.PASS))
            raw = json.dumps(resp.json())
            self.assertIn(schema_id, raw)
        finally:
            self.close_and_delete_wallet(wallet_steward, account_steward)

    def test_create_and_send_credential_def(self):
        account_steward = self.IDENTITY1
        wallet_steward = self.WALLET1_UID
        account_issuer = self.IDENTITY2
        wallet_issuer = self.WALLET2_UID
        self.create_and_open_wallet(wallet_steward, account_steward)
        self.create_and_open_wallet(wallet_issuer, account_issuer)
        try:
            # initialize Steward
            did_steward, verkey_steward = self.ensure_did_exists(account_steward, wallet_steward, '000000000000000000000000Steward1')

            # Issuer
            did_issuer, verkey_issuer = self.create_did(account_issuer, wallet_issuer)

            # Nym request
            url = self.live_server_url + '/agent/admin/wallets/%s/did/%s/ledger/nym_request/' % (wallet_steward, did_steward)
            nym_request = dict(target_did=did_issuer, ver_key=verkey_issuer, role='TRUST_ANCHOR',
                               pass_phrase=self.WALLET_PASS_PHRASE)
            resp = requests.post(url, json=nym_request, auth=HTTPBasicAuth(account_steward, self.PASS))
            self.assertEqual(200, resp.status_code)

            # Schema registration
            schema = {
                'pass_phrase': self.WALLET_PASS_PHRASE,
                'name': 'test_schema_' + uuid.uuid4().hex,
                'version': '1.0',
                'attributes': ["age", "sex", "height", "name"]
            }
            url = self.live_server_url + '/agent/admin/wallets/%s/did/%s/ledger/register_schema/' % (wallet_issuer, did_issuer)
            resp = requests.post(url, json=schema, auth=HTTPBasicAuth(account_issuer, self.PASS))
            self.assertEqual(201, resp.status_code)
            self.assertTrue(resp.json())
            schema_json = resp.json()['schema']

            # Cred Def
            url = self.live_server_url + '/agent/admin/wallets/%s/did/%s/cred_def/create_and_send/' % (wallet_issuer, did_issuer)
            cred_def = {
                'pass_phrase': self.WALLET_PASS_PHRASE,
                'schema_id': schema_json['id'],
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
            url = self.live_server_url + '/agent/admin/wallets/%s/did/%s/cred_def/all/' % (wallet_issuer, did_issuer)
            resp = requests.get(url, auth=HTTPBasicAuth(account_issuer, self.PASS))
            raw = json.dumps(resp.json())
            self.assertIn(schema['name'], raw)
        finally:
            self.close_and_delete_wallet(wallet_steward, account_steward)
            self.close_and_delete_wallet(wallet_issuer, account_issuer)

    @skip(True)
    def test_credential(self):
        account_steward = self.IDENTITY1
        wallet_steward = self.WALLET1_UID
        account_issuer = self.IDENTITY2
        wallet_issuer = self.WALLET2_UID
        account_prover = self.IDENTITY3
        wallet_prover = self.WALLET3_UID
        self.create_and_open_wallet(wallet_steward, account_steward)
        self.create_and_open_wallet(wallet_issuer, account_issuer)
        self.create_and_open_wallet(wallet_prover, account_prover)
        try:
            # initialize Steward
            did_steward, verkey_steward = self.ensure_did_exists(account_steward, wallet_steward, '000000000000000000000000Steward1')
            # Issuer
            did_issuer, verkey_issuer = self.create_did(account_issuer, wallet_issuer)
            url = self.live_server_url + '/agent/admin/wallets/%s/did/%s/ledger/nym_request/' % (wallet_steward, did_steward)
            nym_request = dict(target_did=did_issuer, ver_key=verkey_issuer, role='TRUST_ANCHOR', pass_phrase=self.WALLET_PASS_PHRASE)
            resp = requests.post(url, json=nym_request, auth=HTTPBasicAuth(account_steward, self.PASS))
            self.assertEqual(200, resp.status_code)
            # Prover
            did_prover, verkey_prover = self.create_did(account_prover, wallet_prover)
            url = self.live_server_url + '/agent/admin/wallets/%s/did/%s/ledger/nym_request/' % (wallet_steward, did_steward)
            nym_request = dict(target_did=did_prover, ver_key=verkey_prover, role=None, pass_phrase=self.WALLET_PASS_PHRASE)
            resp = requests.post(url, json=nym_request, auth=HTTPBasicAuth(account_steward, self.PASS))
            self.assertEqual(200, resp.status_code)
            # Schema registration
            schema = {
                'pass_phrase': self.WALLET_PASS_PHRASE,
                'name': 'test_schema_' + uuid.uuid4().hex,
                'version': '1.0',
                'attributes': ["age", "sex", "height", "name"]
            }
            url = self.live_server_url + '/agent/admin/wallets/%s/did/%s/ledger/register_schema/' % (wallet_issuer, did_issuer)
            resp = requests.post(url, json=schema, auth=HTTPBasicAuth(account_issuer, self.PASS))
            self.assertEqual(201, resp.status_code)
            self.assertTrue(resp.json())
            schema_id = resp.json()['schema_id']
            # Cred Def
            url = self.live_server_url + '/agent/admin/wallets/%s/did/%s/cred_def/create_and_send/' % (wallet_issuer, did_issuer)
            cred_def = {
                'pass_phrase': self.WALLET_PASS_PHRASE,
                'schema_id': schema_id,
                'tag': 'TAG1',
                'support_revocation': False
            }
            resp = requests.post(url, json=cred_def, auth=HTTPBasicAuth(account_issuer, self.PASS))
            self.assertEqual(201, resp.status_code)
            cred_def_id = resp.json().get('id')
            cred_def = resp.json().get('cred_def')
            # Issuer: Create credential offer
            url = self.live_server_url + '/agent/admin/wallets/%s/proving/issuer_create_credential_offer/' % wallet_issuer
            params = dict(cred_def_id=cred_def_id, pass_phrase=self.WALLET_PASS_PHRASE)
            resp = requests.post(url, json=params, auth=HTTPBasicAuth(account_issuer, self.PASS))
            self.assertEqual(200, resp.status_code)
            self.assertTrue(resp.json().get('cred_offer'))
            cred_offer = resp.json().get('cred_offer')
            # Prover: Create master key
            prover_link_secret_name = 'my_secret'
            url = self.live_server_url + '/agent/admin/wallets/%s/proving/prover_create_master_secret/' % wallet_prover
            params = dict(link_secret_name=prover_link_secret_name, pass_phrase=self.WALLET_PASS_PHRASE)
            resp = requests.post(url, json=params, auth=HTTPBasicAuth(account_prover, self.PASS))
            self.assertEqual(200, resp.status_code)
            self.assertTrue(resp.json().get('link_secret_id'))
            link_secret_id = resp.json()['link_secret_id']
            # Prover: Credential request
            url = self.live_server_url + '/agent/admin/wallets/%s/proving/prover_create_credential_req/' % wallet_prover
            params = dict(
                pass_phrase=self.WALLET_PASS_PHRASE,
                prover_did=did_prover,
                cred_offer=cred_offer,
                cred_def=cred_def,
                link_secret_id=link_secret_id
            )
            resp = requests.post(url, json=params, auth=HTTPBasicAuth(account_prover, self.PASS))
            self.assertEqual(200, resp.status_code, resp.text)
            self.assertTrue(resp.json().get('cred_req'))
            self.assertTrue(resp.json().get('cred_req_metadata'))
            cred_req = resp.json().get('cred_req')
            cred_req_metadata = resp.json().get('cred_req_metadata')
            # Issuer: Create credential
            url = self.live_server_url + '/agent/admin/wallets/%s/proving/issuer_create_credential/' % wallet_issuer
            params = dict(
                pass_phrase=self.WALLET_PASS_PHRASE,
                cred_offer=cred_offer,
                cred_req=cred_req,
                cred_values=dict(sex='male', name='Alex', height=175, age=28)
            )
            resp = requests.post(url, json=params, auth=HTTPBasicAuth(account_issuer, self.PASS))
            self.assertEqual(200, resp.status_code, resp.text)
            self.assertTrue(resp.json().get('cred'))
            self.assertIn('cred_revoc_id', resp.json().keys())
            self.assertIn('revoc_reg_delta', resp.json().keys())
            cred = resp.json().get('cred')
            # Prover: store credentials
            url = self.live_server_url + '/agent/admin/wallets/%s/proving/prover_store_credential/' % wallet_prover
            params = dict(
                pass_phrase=self.WALLET_PASS_PHRASE,
                cred_req_metadata=cred_req_metadata,
                cred=cred,
                cred_def=cred_def
            )
            resp = requests.post(url, json=params, auth=HTTPBasicAuth(account_prover, self.PASS))
            self.assertEqual(200, resp.status_code, resp.text)
            self.assertTrue(resp.json().get('cred_id'))
        finally:
            self.close_and_delete_wallet(wallet_steward, account_steward)
            self.close_and_delete_wallet(wallet_issuer, account_issuer)
            self.close_and_delete_wallet(wallet_prover, account_prover)

    def test_verify_credential(self):
        account_steward = self.IDENTITY1
        wallet_steward = self.WALLET1_UID
        account_issuer = self.IDENTITY2
        wallet_issuer = self.WALLET2_UID
        account_prover = self.IDENTITY3
        wallet_prover = self.WALLET3_UID
        self.create_and_open_wallet(wallet_steward, account_steward)
        self.create_and_open_wallet(wallet_issuer, account_issuer)
        self.create_and_open_wallet(wallet_prover, account_prover)
        try:
            # initialize Steward
            did_steward, verkey_steward = self.ensure_did_exists(account_steward, wallet_steward, '000000000000000000000000Steward1')
            # Issuer
            did_issuer, verkey_issuer = self.create_did(account_issuer, wallet_issuer)
            url = self.live_server_url + '/agent/admin/wallets/%s/did/%s/ledger/nym_request/' % (wallet_steward, did_steward)
            nym_request = dict(target_did=did_issuer, ver_key=verkey_issuer, role='TRUST_ANCHOR', pass_phrase=self.WALLET_PASS_PHRASE)
            resp = requests.post(url, json=nym_request, auth=HTTPBasicAuth(account_steward, self.PASS))
            self.assertEqual(200, resp.status_code)
            # Prover
            did_prover, verkey_prover = self.create_did(account_prover, wallet_prover)
            url = self.live_server_url + '/agent/admin/wallets/%s/did/%s/ledger/nym_request/' % (wallet_steward, did_steward)
            nym_request = dict(target_did=did_prover, ver_key=verkey_prover, role=None, pass_phrase=self.WALLET_PASS_PHRASE)
            resp = requests.post(url, json=nym_request, auth=HTTPBasicAuth(account_steward, self.PASS))
            self.assertEqual(200, resp.status_code)
            # Schema registration
            schema = {
                'pass_phrase': self.WALLET_PASS_PHRASE,
                'name': 'test_schema_' + uuid.uuid4().hex,
                'version': '1.0',
                'attributes': ["age", "sex", "height", "name"]
            }
            url = self.live_server_url + '/agent/admin/wallets/%s/did/%s/ledger/register_schema/' % (wallet_issuer, did_issuer)
            resp = requests.post(url, json=schema, auth=HTTPBasicAuth(account_issuer, self.PASS))
            self.assertEqual(201, resp.status_code)
            self.assertTrue(resp.json())
            schema_id = resp.json()['schema_id']
            # Cred Def
            url = self.live_server_url + '/agent/admin/wallets/%s/did/%s/cred_def/create_and_send/' % (wallet_issuer, did_issuer)
            cred_def = {
                'pass_phrase': self.WALLET_PASS_PHRASE,
                'schema_id': schema_id,
                'tag': 'TAG1',
                'support_revocation': False
            }
            resp = requests.post(url, json=cred_def, auth=HTTPBasicAuth(account_issuer, self.PASS))
            self.assertEqual(201, resp.status_code)
            cred_def_id = resp.json().get('id')
            cred_def = resp.json().get('cred_def')
            # Issuer: Create credential offer
            url = self.live_server_url + '/agent/admin/wallets/%s/proving/issuer_create_credential_offer/' % wallet_issuer
            params = dict(cred_def_id=cred_def_id, pass_phrase=self.WALLET_PASS_PHRASE)
            resp = requests.post(url, json=params, auth=HTTPBasicAuth(account_issuer, self.PASS))
            self.assertEqual(200, resp.status_code)
            self.assertTrue(resp.json().get('cred_offer'))
            cred_offer = resp.json().get('cred_offer')
            # Prover: Create master key
            prover_link_secret_name = 'my_secret'
            url = self.live_server_url + '/agent/admin/wallets/%s/proving/prover_create_master_secret/' % wallet_prover
            params = dict(link_secret_name=prover_link_secret_name, pass_phrase=self.WALLET_PASS_PHRASE)
            resp = requests.post(url, json=params, auth=HTTPBasicAuth(account_prover, self.PASS))
            self.assertEqual(200, resp.status_code)
            self.assertTrue(resp.json().get('link_secret_id'))
            link_secret_id = resp.json()['link_secret_id']
            # Prover: Credential request
            url = self.live_server_url + '/agent/admin/wallets/%s/proving/prover_create_credential_req/' % wallet_prover
            params = dict(
                pass_phrase=self.WALLET_PASS_PHRASE,
                prover_did=did_prover,
                cred_offer=cred_offer,
                cred_def=cred_def,
                link_secret_id=link_secret_id
            )
            resp = requests.post(url, json=params, auth=HTTPBasicAuth(account_prover, self.PASS))
            self.assertEqual(200, resp.status_code, resp.text)
            self.assertTrue(resp.json().get('cred_req'))
            self.assertTrue(resp.json().get('cred_req_metadata'))
            cred_req = resp.json().get('cred_req')
            cred_req_metadata = resp.json().get('cred_req_metadata')
            # Issuer: Create credential
            url = self.live_server_url + '/agent/admin/wallets/%s/proving/issuer_create_credential/' % wallet_issuer
            params = dict(
                pass_phrase=self.WALLET_PASS_PHRASE,
                cred_offer=cred_offer,
                cred_req=cred_req,
                cred_values=dict(sex='male', name='Alex', height=175, age=28)
            )
            resp = requests.post(url, json=params, auth=HTTPBasicAuth(account_issuer, self.PASS))
            self.assertEqual(200, resp.status_code, resp.text)
            self.assertTrue(resp.json().get('cred'))
            self.assertIn('cred_revoc_id', resp.json().keys())
            self.assertIn('revoc_reg_delta', resp.json().keys())
            cred = resp.json().get('cred')
            # Prover: store credentials
            url = self.live_server_url + '/agent/admin/wallets/%s/proving/prover_store_credential/' % wallet_prover
            params = dict(
                pass_phrase=self.WALLET_PASS_PHRASE,
                cred_req_metadata=cred_req_metadata,
                cred=cred,
                cred_def=cred_def
            )
            resp = requests.post(url, json=params, auth=HTTPBasicAuth(account_prover, self.PASS))
            self.assertEqual(200, resp.status_code, resp.text)
            self.assertTrue(resp.json().get('cred_id'))
            # Prover gets Credentials for Proof Request
            proof_request = {
                'nonce': '123432421212',
                'name': 'proof_req_1',
                'version': '0.1',
                'requested_attributes': {
                    'attr1_referent': {
                        'name': 'name',
                        "restrictions": {
                            "issuer_did": did_issuer,
                            "schema_id": schema_id
                        }
                    }
                },
                'requested_predicates': {
                    'predicate1_referent': {
                        'name': 'age',
                        'p_type': '>=',
                        'p_value': 18,
                        "restrictions": {
                            "issuer_did": did_issuer
                        }
                    }
                }
            }
            # Prover gets Credentials for attr1_referent anf predicate1_referent
            url = self.live_server_url + '/agent/admin/wallets/%s/proving/prover_search_credentials_for_proof_req/' % wallet_prover
            params = dict(
                pass_phrase=self.WALLET_PASS_PHRASE,
                proof_req=proof_request,
            )
            resp = requests.post(url, json=params, auth=HTTPBasicAuth(account_prover, self.PASS))
            self.assertEqual(200, resp.status_code, resp.text)
            search_handle = resp.json()['search_handle']
            try:
                url = self.live_server_url + '/agent/admin/wallets/%s/proving/prover_fetch_credentials_for_proof_req/' % wallet_prover
                params = dict(
                    pass_phrase=self.WALLET_PASS_PHRASE,
                    search_handle=search_handle
                )
                # attr1_referent
                params.update(dict(item_referent='attr1_referent', count=1))
                resp = requests.post(url, json=params, auth=HTTPBasicAuth(account_prover, self.PASS))
                self.assertEqual(200, resp.status_code, resp.text)
                prover_cred_for_attr1 = resp.json()[0]['cred_info']
                # predicate1_referent
                params.update(dict(item_referent='predicate1_referent', count=1))
                resp = requests.post(url, json=params, auth=HTTPBasicAuth(account_prover, self.PASS))
                self.assertEqual(200, resp.status_code, resp.text)
                prover_cred_for_predicate1 = resp.json()[0]['cred_info']
            finally:
                url = self.live_server_url + '/agent/admin/wallets/%s/proving/prover_close_credentials_search_for_proof_req/' % wallet_prover
                params = dict(
                    pass_phrase=self.WALLET_PASS_PHRASE,
                    search_handle=search_handle,
                )
                resp = requests.post(url, json=params, auth=HTTPBasicAuth(account_prover, self.PASS))
                print('Close status: %d' % resp.status_code)
            # Prover declare requested creds
            prover_requested_creds = {
                'self_attested_attributes': {},
                'requested_attributes': {
                    'attr1_referent': {
                        'cred_id': prover_cred_for_attr1['referent'],
                        'revealed': True
                    }
                },
                'requested_predicates': {
                    'predicate1_referent': {
                        'cred_id': prover_cred_for_predicate1['referent']
                    }
                }
            }
            # Prover load entities from ledger
            url = self.live_server_url + '/agent/ledger/prover_get_entities/'
            identifiers = {
                prover_cred_for_attr1['referent']: prover_cred_for_attr1,
                prover_cred_for_predicate1['referent']: prover_cred_for_predicate1
            }
            params = dict(
                identifiers=identifiers
            )
            resp = requests.post(url, json=params, auth=HTTPBasicAuth(account_prover, self.PASS))
            self.assertEqual(200, resp.status_code, resp.text)
            schemas = resp.json()['schemas']
            cred_defs = resp.json()['cred_defs']
            rev_states = resp.json()['rev_states']
            # Prover creates Proof for Proof Request
            url = self.live_server_url + '/agent/admin/wallets/%s/proving/prover_create_proof/' % wallet_prover
            params = dict(
                pass_phrase=self.WALLET_PASS_PHRASE,
                proof_req=proof_request,
                requested_creds=prover_requested_creds,
                link_secret_id=link_secret_id,
                schemas=schemas,
                cred_defs=cred_defs,
                rev_states=rev_states
            )
            resp = requests.post(url, json=params, auth=HTTPBasicAuth(account_prover, self.PASS))
            self.assertEqual(200, resp.status_code)
            proof = resp.json()
            self.assertEqual('Alex', proof['requested_proof']['revealed_attrs']['attr1_referent']["raw"])
            # Verifier load entities from ledger
            url = self.live_server_url + '/agent/ledger/verifier_get_entities/'
            params = dict(
                identifiers=proof['identifiers']
            )
            resp = requests.post(url, json=params, auth=HTTPBasicAuth(account_steward, self.PASS))
            self.assertEqual(200, resp.status_code, resp.text)
            schemas = resp.json()['schemas']
            cred_defs = resp.json()['cred_defs']
            rev_reg_defs = resp.json()['rev_reg_defs']
            rev_regs = resp.json()['rev_regs']
            # Verifier is verifying proof from Prover
            url = self.live_server_url + '/agent/verify/verify_proof/'
            params = dict(
                proof_req=proof_request,
                proof=proof,
                schemas=schemas,
                cred_defs=cred_defs,
                rev_reg_defs=rev_reg_defs,
                rev_regs=rev_regs
            )
            resp = requests.post(url, json=params, auth=HTTPBasicAuth(account_steward, self.PASS))
            self.assertEqual(200, resp.status_code, resp.text)
            self.assertTrue(resp.json()['success'])
        finally:
            self.close_and_delete_wallet(wallet_steward, account_steward)
            self.close_and_delete_wallet(wallet_issuer, account_issuer)
            self.close_and_delete_wallet(wallet_prover, account_prover)
