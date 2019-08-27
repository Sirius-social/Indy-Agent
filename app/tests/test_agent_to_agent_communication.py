import os
import json
import asyncio
from time import sleep

import requests
from requests.auth import HTTPBasicAuth
from django.test import LiveServerTestCase
from django.urls import reverse
from django.db import connection

from authentication.models import AgentAccount
from api.models import Wallet as WalletModel
from transport.models import Endpoint as EndpointModel, Invitation as InvitationModel
from core.wallet import WalletConnection, WalletAgent, AgentTimeOutError
from core.sync2async import run_async, ThreadScheduler


def get_ps_ax():
    pipe = os.popen('ps ax')
    output = pipe.read()
    return output


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

    def test_invite(self):
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
        endpoint_invitee = AgentAccount.objects.get(username=self.IDENTITY_AGENT2).endpoints.first()
        endpoint_invitee.url = self.live_server_url + reverse(
            'endpoint',
            kwargs=dict(uid=AgentAccount.objects.get(username=self.IDENTITY_AGENT2).endpoints.first().uid)
        )
        endpoint_invitee.save()
        invitee = dict(
            identity=self.IDENTITY_AGENT2,
            password=self.IDENTITY_PASS,
            wallet_uid=AgentAccount.objects.get(username=self.IDENTITY_AGENT2).wallets.first().uid,
            endpoint_uid=AgentAccount.objects.get(username=self.IDENTITY_AGENT2).endpoints.first().uid,
            endpoint_url=endpoint_invitee.url
        )
        # Step 1: generate invitation link
        url = self.live_server_url + '/agent/admin/wallets/%s/endpoints/%s/invitations/' % \
              (inviter['wallet_uid'], inviter['endpoint_uid'])
        resp = requests.post(url, json=cred, auth=HTTPBasicAuth(inviter['identity'], inviter['password']))
        self.assertEqual(201, resp.status_code, resp.text)
        invite_url_string = resp.json()['url']
        print('Invitation LINK: %s' % invite_url_string)
        # Step 2: send invite to Invitee
        url = self.live_server_url + '/agent/admin/wallets/%s/endpoints/%s/invite/' % \
              (invitee['wallet_uid'], invitee['endpoint_uid'])
        invite = dict(**cred)
        invite['url'] = invite_url_string
        resp = requests.post(url, json=invite, auth=HTTPBasicAuth(invitee['identity'], invitee['password']))
        self.assertEqual(202, resp.status_code)
        sleep(5)
        # Check pairwise list
        all_pairwises = []
        for actor in [inviter, invitee]:
            url = self.live_server_url + '/agent/admin/wallets/%s/pairwise/all/' % actor['wallet_uid']
            resp = requests.post(url, json=cred, auth=HTTPBasicAuth(actor['identity'], actor['password']))
            self.assertEqual(200, resp.status_code, resp.text)
            ret = resp.json()
            self.assertEqual(1, len(ret))
            pairwise = ret[0]
            all_pairwises.append(pairwise)
            url = self.live_server_url + '/agent/admin/wallets/%s/pairwise/get_metadata/' % actor['wallet_uid']
            did_access = dict(**cred)
            did_access['their_did'] = pairwise['their_did']
            resp = requests.post(url, json=did_access, auth=HTTPBasicAuth(actor['identity'], actor['password']))
            self.assertEqual(200, resp.status_code, resp.text)
            ret = resp.json()
            did_access['their_did'] = pairwise['my_did']
            resp = requests.post(url, json=did_access, auth=HTTPBasicAuth(actor['identity'], actor['password']))
            self.assertEqual(400, resp.status_code, resp.text)
            pass
        print('======== ALL PAIRWISE =========')
        print(json.dumps(all_pairwises, indent=2, sort_keys=True))
        print('===============================')
        pass
