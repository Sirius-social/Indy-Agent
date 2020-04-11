from urllib.parse import urljoin

import os
import json
import base64
import uuid
import asyncio
from time import sleep
from unittest import skip

import requests
from requests.auth import HTTPBasicAuth
from django.conf import settings
from django.test import LiveServerTestCase, override_settings
from django.urls import reverse
from django.db import connection

from authentication.models import AgentAccount
from api.models import Wallet as WalletModel
from transport.models import Endpoint as EndpointModel
from core.const import WALLET_KEY_TO_DID_KEY
from core.wallet import WalletConnection, WalletAgent, AgentTimeOutError
from core.sync2async import run_async, ThreadScheduler
from core.utils import HEADER_PASS_PHRASE


def get_ps_ax():
    pipe = os.popen('ps ax')
    output = pipe.read()
    return output


def get_indy_agent(path):
    url = urljoin('https://socialsirius.com', path)
    resp = requests.get(url, verify=False, auth=HTTPBasicAuth('demo', 'demo'))
    return resp


def post_indy_agent(path, json_: dict = None):
    url = urljoin('https://socialsirius.com', path)
    resp = requests.post(url, json=json_, verify=False, auth=HTTPBasicAuth('demo', 'demo'))
    return resp


OVERRIDDEN_INDY_SETTINGS = settings.INDY
OVERRIDDEN_INDY_SETTINGS['WALLET_SETTINGS']['PROVER_MASTER_SECRET_NAME'] = 'test'
OVERRIDDEN_INDY_SETTINGS['GENESIS_TXN_FILE_PATH'] = '/ci/test_sirius_pool_transactions_genesis'


@override_settings(INDY=OVERRIDDEN_INDY_SETTINGS)
class Agent2AgentCommunicationTest(LiveServerTestCase):

    IDENTITY_AGENT1 = 'agent1_user'
    IDENTITY_AGENT2 = 'agent2_user'
    IDENTITY_PASS = 'pass'
    WALLET_AGENT1 = 'wallet_1'
    WALLET_AGENT2 = 'wallet_2'
    WALLET_PASS_PHRASE = 'pass'
    WALLET_AGENT1_DB_NAME = WalletConnection.make_wallet_address(WALLET_AGENT1)
    WALLET_AGENT2_DB_NAME = WalletConnection.make_wallet_address(WALLET_AGENT2)
    DEF_TIMEOUT = 5

    def setUp(self):
        for identity in [self.IDENTITY_AGENT1, self.IDENTITY_AGENT2]:
            account = AgentAccount.objects.create(username=identity, is_active=True, is_staff=True)
            account.set_password(self.IDENTITY_PASS)
            account.save()
        os.popen("pkill -f run_wallet_agent")
        sleep(0.1)
        psax = get_ps_ax()
        self.assertNotIn('run_wallet_agent', psax, psax)
        with connection.cursor() as cursor:
            for db_name in [self.WALLET_AGENT1_DB_NAME, self.WALLET_AGENT2_DB_NAME]:
                cursor.execute("DROP DATABASE  IF EXISTS %s" % db_name)
        self.agents = []
        self.agents_logs = dict()
        self.agents_logs[self.IDENTITY_AGENT1] = list()
        self.agents_logs[self.IDENTITY_AGENT2] = list()
        self.start_agents()

    def tearDown(self):
        self.stop_agents()
        sleep(1)
        os.popen("pkill -f run_wallet_agent")
        sleep(1)

    def start_agents(self):

        async def start_agent(agent_name, pass_phrase):
            conn = WalletConnection(agent_name, pass_phrase)
            await conn.create()
            try:
                print('Agent "%s" is started' % agent_name)
                await WalletAgent.process(agent_name)
            finally:
                await conn.delete()
                print('Wallet "%s" is deleted' % agent_name)

        for agent, identity in [(self.WALLET_AGENT1, self.IDENTITY_AGENT1), (self.WALLET_AGENT2, self.IDENTITY_AGENT2)]:
            thread = ThreadScheduler()
            self.agents.append(thread)
            thread.start()
            asyncio.run_coroutine_threadsafe(
                start_agent(agent, self.WALLET_PASS_PHRASE), loop=thread.loop
            )
            account = AgentAccount.objects.get(username=identity)
            model_wallet = WalletModel.objects.create(uid=agent, owner=account)
            endpoint_uid = 'endpoint_for_' + agent
            EndpointModel.objects.create(
                uid=endpoint_uid, owner=account, wallet=model_wallet,
                url=reverse('endpoint', kwargs=dict(uid=endpoint_uid))
            )

        sleep(10)
    pass

    def stop_agents(self):

        async def stop_agent(agent_name, pass_phrase):
            try:
                await WalletAgent.close(agent_name, pass_phrase)
            except AgentTimeOutError:
                pass

        for agent in [self.WALLET_AGENT1, self.WALLET_AGENT2]:
            run_async(stop_agent(agent, self.WALLET_PASS_PHRASE))
        sleep(5)
        for thread in self.agents:
            thread.stop()
    pass

    def create_did(self, wallet_uid: str, seed: str=None):
        run_async(
            WalletAgent.open(wallet_uid, self.WALLET_PASS_PHRASE)
        )
        did, verkey = run_async(
            WalletAgent.create_and_store_my_did(
                wallet_uid, self.WALLET_PASS_PHRASE, seed
            )
        )
        run_async(
            WalletAgent.add_wallet_record(wallet_uid, self.WALLET_PASS_PHRASE, WALLET_KEY_TO_DID_KEY, verkey, did)
        )
        return did, verkey

    async def register_schema(self, wallet_uid: str, schema: dict, did: str):
        await WalletAgent.open(wallet_uid, self.WALLET_PASS_PHRASE)
        schema_request, schema_json = await WalletAgent.build_schema_request(
            wallet_uid, self.WALLET_PASS_PHRASE, did, schema['name'], schema['version'], schema['attributes']
        )
        schema_response = await WalletAgent.sign_and_submit_request(
            wallet_uid, self.WALLET_PASS_PHRASE, did, schema_request
        )
        assert schema_response['op'] == 'REPLY'

        cred_def_id, cred_def_json, cred_def_request, schema = await WalletAgent.issuer_create_credential_def(
            wallet_uid, self.WALLET_PASS_PHRASE, did, schema_json['id'], 'TAG', False
        )
        return cred_def_id, cred_def_json, cred_def_request, schema

    async def register_pairwise(
            self, wallet_uid: str, their_did: str, my_did: str, their_vk: str, my_vk: str,
            their_endpoint: str, label: str
    ):
        metadata = {
            'label': label,
            'their_endpoint': their_endpoint,
            'their_vk': their_vk,
            'my_vk': my_vk,
        }
        await WalletAgent.create_pairwise_statically(
            wallet_uid, self.WALLET_PASS_PHRASE, their_did, their_vk, my_did, metadata
        )

    @skip(True)
    def test_demo_issuer__feature_0037(self):
        """Тест на проблмы верификации credentials Android агента по feature 0037"""
        # Setup issuer
        endpoint_issuer = AgentAccount.objects.get(username=self.IDENTITY_AGENT1).endpoints.first()
        endpoint_issuer.url = self.live_server_url + reverse(
            'endpoint',
            kwargs=dict(uid=AgentAccount.objects.get(username=self.IDENTITY_AGENT1).endpoints.first().uid)
        )
        endpoint_issuer.save()
        issuer = dict(
            account=self.IDENTITY_AGENT1,
            wallet=AgentAccount.objects.get(username=self.IDENTITY_AGENT1).wallets.first().uid,
            password=self.IDENTITY_PASS,
            endpoint_uid=AgentAccount.objects.get(username=self.IDENTITY_AGENT1).endpoints.first().uid,
            endpoint_url=endpoint_issuer.url
        )
        # Setup holder
        endpoint_holder = AgentAccount.objects.get(username=self.IDENTITY_AGENT2).endpoints.first()
        endpoint_holder.url = self.live_server_url + reverse(
            'endpoint',
            kwargs=dict(uid=AgentAccount.objects.get(username=self.IDENTITY_AGENT2).endpoints.first().uid)
        )
        endpoint_holder.save()
        holder = dict(
            account=self.IDENTITY_AGENT2,
            wallet=AgentAccount.objects.get(username=self.IDENTITY_AGENT2).wallets.first().uid,
            password=self.IDENTITY_PASS,
            endpoint_uid=AgentAccount.objects.get(username=self.IDENTITY_AGENT2).endpoints.first().uid,
            endpoint_url=endpoint_holder.url
        )
        # Setup DID, VerKeys and schemas
        issuer_seed = '000000000000000000000000Steward1'
        holder_seed = '00000000000000000000000000Holder'
        did_issuer, verkey_issuer = self.create_did(issuer['wallet'], issuer_seed)
        did_holder, verkey_holder = self.create_did(holder['wallet'], holder_seed)

        # Exchange pairwise dids
        run_async(
            self.register_pairwise(
                wallet_uid=issuer['wallet'],
                their_did=did_holder, their_vk=verkey_holder,
                my_did=did_issuer, my_vk=verkey_issuer,
                their_endpoint=holder['endpoint_url'],
                label='Holder'
            )
        )
        run_async(
            self.register_pairwise(
                wallet_uid=holder['wallet'],
                their_did=did_issuer, their_vk=verkey_issuer,
                my_did=did_holder, my_vk=verkey_holder,
                their_endpoint=issuer['endpoint_url'],
                label='Issuer'
            )
        )
        # Load schema and cred-defs meta
        path = '/agent/admin/wallets/demo_issuer/did/%s/ledger/schemas/' % did_issuer
        resp = get_indy_agent(path)
        assert resp.status_code == 200
        print('=========== SCHEMAS ============')
        print(json.dumps(resp.json(), indent=2, sort_keys=True))
        print('================================')
        registered_schema = list(
            filter(lambda s: s['name'] == 'Transcript' and s['version'] == '1.2', resp.json())
        )[0]
        resp = get_indy_agent('/agent/admin/wallets/demo_issuer/did/%s/cred_def/all/' % did_issuer)
        assert resp.status_code == 200
        print('=========== CRED-DEFs ============')
        print(json.dumps(resp.json(), indent=2, sort_keys=True))
        print('================================')
        registered_creddef = list(
            filter(lambda cd: cd['schema']['id'] == registered_schema['id'], resp.json())
        )[0]
        credential = dict(
            birthday='Value for birthday',
            ssn='Value for ssn',
            first_name='Value for first_name',
            last_name='Value for last_name'
        )
        params = dict(
            cred_def_id=registered_creddef['id'],
            cred_def=registered_creddef['cred_def'],
            issuer_schema=registered_schema,
            their_did=did_holder,
            values=credential,
            pass_phrase='pass'
        )
        cred_req_meta = run_async(
            WalletAgent.issuer_create_credential_def(
                agent_name=issuer['wallet'],
                pass_phrase=self.WALLET_PASS_PHRASE,
                self_did=did_issuer,
                schema_id=registered_schema['id'],
                tag='DEMO',
                support_revocation=False
            )
        )
        url = self.live_server_url + '/agent/admin/wallets/%s/messaging/issue_credential/' % issuer['wallet']
        resp = requests.post(url, json=params, auth=HTTPBasicAuth(issuer['account'], issuer['password']))
        self.assertEqual(resp.status_code, 200, resp.text)
        log = resp.json()
        self.assertTrue(log)
        print('------- LOG -----------')
        print(json.dumps(log, indent=2))
        print('------------------------')
