import os
import re
import json
import base64
import uuid
import asyncio
import subprocess
from time import sleep
from unittest import skip

import requests
from requests.auth import HTTPBasicAuth
from django.test import LiveServerTestCase
from django.urls import reverse
from django.db import connection

from authentication.models import AgentAccount
from api.models import Wallet as WalletModel
from transport.models import Endpoint as EndpointModel
from core.const import WALLET_KEY_TO_DID_KEY
from core.wallet import WalletConnection, WalletAgent, AgentTimeOutError
from core.sync2async import run_async, ThreadScheduler

from .utils import ProvisionConfig, Invitation
from .usecases import alice_create_connection


def get_ps_ax():
    pipe = os.popen('ps ax')
    output = pipe.read()
    return output


class VCXCompatibilityTest(LiveServerTestCase):

    IDENTITY_AGENT1 = 'agent1_user'
    IDENTITY_AGENT2 = 'agent2_user'
    IDENTITY_PASS = 'pass'
    WALLET_AGENT1 = 'wallet_1'
    WALLET_AGENT2 = 'wallet_2'
    WALLET_PASS_PHRASE = 'pass'
    WALLET_AGENT1_DB_NAME = WalletConnection.make_wallet_address(WALLET_AGENT1)
    WALLET_AGENT2_DB_NAME = WalletConnection.make_wallet_address(WALLET_AGENT2)
    DEF_TIMEOUT = 3

    def setUp(self):
        for identity in [self.IDENTITY_AGENT1, self.IDENTITY_AGENT2]:
            account = AgentAccount.objects.create(username=identity, is_active=True, is_staff=True)
            account.set_password(self.IDENTITY_PASS)
            account.save()
        os.popen("pkill -f run_wallet_agent")
        sleep(0.1)
        psax = get_ps_ax()
        self.assertNotIn('run_wallet_agent', psax, psax)
        self.assertNotIn('indy-dummy-agent', psax, psax)
        with connection.cursor() as cursor:
            for db_name in [self.WALLET_AGENT1_DB_NAME, self.WALLET_AGENT2_DB_NAME]:
                cursor.execute("DROP DATABASE  IF EXISTS %s" % db_name)
        self.agents = []
        self.agents_logs = dict()
        self.agents_logs[self.IDENTITY_AGENT1] = list()
        self.agents_logs[self.IDENTITY_AGENT2] = list()
        self.start_agents()
        self.start_dummy_cloud_agent()

    def tearDown(self):
        self.stop_agents()
        sleep(1)
        os.popen("pkill -f run_wallet_agent")
        os.popen("pkill -f indy-dummy-agent")
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

        sleep(self.DEF_TIMEOUT)
    pass

    def start_dummy_cloud_agent(self):
        exe = "/dummy-cloud-agent/target/release/indy-dummy-agent"
        config = "/dummy-cloud-agent/config/sample-config.json"
        cmd_line = '%s %s' % (exe, config)
        args = cmd_line.split()
        process = subprocess.Popen(args)
        stat = process.poll()
        self.assertIsNone(stat)

    def stop_agents(self):

        async def stop_agent(agent_name, pass_phrase):
            try:
                await WalletAgent.close(agent_name, pass_phrase)
            except AgentTimeOutError:
                pass

        for agent in [self.WALLET_AGENT1, self.WALLET_AGENT2]:
            run_async(stop_agent(agent, self.WALLET_PASS_PHRASE))
        sleep(self.DEF_TIMEOUT)
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

    @skip(True)
    def test_connection(self):
        cred = dict(pass_phrase=self.WALLET_PASS_PHRASE)
        endpoint_inviter = AgentAccount.objects.get(username=self.IDENTITY_AGENT1).endpoints.first()
        endpoint_inviter.url = self.live_server_url + reverse(
            'endpoint',
            kwargs=dict(uid=AgentAccount.objects.get(username=self.IDENTITY_AGENT1).endpoints.first().uid)
        )
        endpoint_inviter.save()
        inviter = dict(
            identity=self.IDENTITY_AGENT1,
            password=self.IDENTITY_PASS,
            wallet_uid=AgentAccount.objects.get(username=self.IDENTITY_AGENT1).wallets.first().uid,
            endpoint_uid=AgentAccount.objects.get(username=self.IDENTITY_AGENT1).endpoints.first().uid,
            endpoint_url=endpoint_inviter.url
        )
        # generate invitation link
        url = self.live_server_url + '/agent/admin/wallets/%s/endpoints/%s/invitations/' % \
              (inviter['wallet_uid'], inviter['endpoint_uid'])
        invitation_kwargs = dict(**cred)
        invitation_kwargs['feature'] = 'feature_0160'
        resp = requests.post(url, json=invitation_kwargs, auth=HTTPBasicAuth(inviter['identity'], inviter['password']))
        self.assertEqual(201, resp.status_code, resp.text)
        # Parse invitation message body
        link = resp.json()['url']
        matches = re.match("(.+)?c_i=(.+)", link)
        buffer = base64.urlsafe_b64decode(matches.group(2)).decode('utf-8')
        msg = json.loads(buffer)

        alice_vcx_config = ProvisionConfig(
            agency_url='http://localhost:8080',
            agency_did='VsKV7grR1BUE29mG2Fm2kX',
            agency_verkey='Hezce2UWMZ3wUhVkh2LfKSs8nDzWwzs2Win7EzNN3YaR',
            wallet_name='alice_wallet',
            enterprise_seed='000000000000000000000000Trustee1'
        )
        alice_vcx_invitation = Invitation(
            label=msg['label'],
            recipient_keys=msg['recipientKeys'],
            service_endpoint=msg['serviceEndpoint'],
            routing_keys=[]
        )
        run_async(
            alice_create_connection(
                alice=alice_vcx_config,
                invitation=alice_vcx_invitation
            ),
            timeout=1000
        )
        sleep(1000)
