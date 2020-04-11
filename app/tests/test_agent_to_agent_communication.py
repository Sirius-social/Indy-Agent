import os
import json
import base64
import uuid
import asyncio
from time import sleep

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
from core.utils import HEADER_PASS_PHRASE


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
        return cred_def_id, cred_def_json, cred_def_request, schema_json

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

    def test_invite_feature_0023(self):
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
        invitation_kwargs = dict(**cred)
        invitation_kwargs['feature'] = 'feature_0023'
        resp = requests.post(url, json=invitation_kwargs, auth=HTTPBasicAuth(inviter['identity'], inviter['password']))
        self.assertEqual(201, resp.status_code, resp.text)
        invite_url_string = resp.json()['url']
        print('Invitation LINK: %s' % invite_url_string)
        # Step 2: send invite to Invitee
        url = self.live_server_url + '/agent/admin/wallets/%s/endpoints/%s/invite/' % \
              (invitee['wallet_uid'], invitee['endpoint_uid'])
        invite = dict(**cred)
        invite['url'] = invite_url_string
        resp = requests.post(url, json=invite, auth=HTTPBasicAuth(invitee['identity'], invitee['password']))
        self.assertEqual(200, resp.status_code)
        log = resp.json()
        self.assertTrue(log)
        print('======== INVITE LOG =========')
        print(json.dumps(log, indent=2, sort_keys=True))
        print('===============================')
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

    def test_invite_feature_0160(self):
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
        invitation_kwargs = dict(**cred)
        invitation_kwargs['feature'] = 'feature_0160'
        resp = requests.post(url, json=invitation_kwargs, auth=HTTPBasicAuth(inviter['identity'], inviter['password']))
        self.assertEqual(201, resp.status_code, resp.text)
        invite_url_string = resp.json()['url']
        print('Invitation LINK: %s' % invite_url_string)
        # Step 2: send invite to Invitee
        url = self.live_server_url + '/agent/admin/wallets/%s/endpoints/%s/invite/' % \
              (invitee['wallet_uid'], invitee['endpoint_uid'])
        invite = dict(**cred)
        invite['url'] = invite_url_string
        resp = requests.post(url, json=invite, auth=HTTPBasicAuth(invitee['identity'], invitee['password']))
        self.assertEqual(200, resp.status_code)
        log = resp.json()
        self.assertTrue(log)
        print('======== INVITE LOG =========')
        print(json.dumps(log, indent=2, sort_keys=True))
        print('===============================')
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

    def test_invite_feature_0160_fixed_did(self):
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
        did_inviter, verkey_inviter = self.create_did(inviter['wallet_uid'])
        url = self.live_server_url + '/agent/admin/wallets/%s/endpoints/%s/invitations/ensure_exists/' % \
              (inviter['wallet_uid'], inviter['endpoint_uid'])
        invitation_kwargs = dict(**cred)
        invitation_kwargs['my_did'] = did_inviter
        invitation_kwargs['seed'] = 'invitation-seed'
        resp = requests.post(url, json=invitation_kwargs, auth=HTTPBasicAuth(inviter['identity'], inviter['password']))
        self.assertEqual(200, resp.status_code, resp.text)
        invite_url_string = resp.json()['url']
        print('Invitation LINK: %s' % invite_url_string)
        # Step 2: send invite to Invitee
        did_invitee, verkey_invitee = self.create_did(invitee['wallet_uid'])
        url = self.live_server_url + '/agent/admin/wallets/%s/endpoints/%s/invite/' % \
              (invitee['wallet_uid'], invitee['endpoint_uid'])
        invite = dict(**cred)
        invite['url'] = invite_url_string
        invite['my_did'] = did_invitee
        resp = requests.post(url, json=invite, auth=HTTPBasicAuth(invitee['identity'], invitee['password']))
        self.assertEqual(200, resp.status_code)
        log = resp.json()
        self.assertTrue(log)
        print('======== INVITE LOG =========')
        print(json.dumps(log, indent=2, sort_keys=True))
        print('===============================')
        # Check pairwise list
        url = self.live_server_url + '/agent/admin/wallets/%s/pairwise/all/' % invitee['wallet_uid']
        resp = requests.post(url, json=cred, auth=HTTPBasicAuth(invitee['identity'], invitee['password']))
        self.assertEqual(200, resp.status_code, resp.text)
        ret = resp.json()
        self.assertIn(did_inviter, str(ret))
        url = self.live_server_url + '/agent/admin/wallets/%s/pairwise/all/' % inviter['wallet_uid']
        resp = requests.post(url, json=cred, auth=HTTPBasicAuth(inviter['identity'], inviter['password']))
        self.assertEqual(200, resp.status_code, resp.text)
        ret = resp.json()
        self.assertIn(did_invitee, str(ret))

    def test_invite_feature_0160_update_pairwise(self):
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
        # Step 1: generate pairwices statically
        headers = dict()
        headers[HEADER_PASS_PHRASE] = self.WALLET_PASS_PHRASE
        did_inviter, verkey_inviter = self.create_did(inviter['wallet_uid'])
        did_invitee, verkey_invitee = self.create_did(invitee['wallet_uid'])
        url = self.live_server_url + '/agent/admin/wallets/%s/pairwise/create_pairwise_statically/' % inviter['wallet_uid']
        pairwise_inviter = dict(
            my_did=did_inviter,
            their_did=did_invitee,
            their_verkey=verkey_invitee,
            metadata={
                'their_endpoint': invitee['endpoint_url'],
                'their_vk': verkey_invitee,
                'my_vk': verkey_inviter,
            }
        )
        resp = requests.post(url, json=pairwise_inviter, auth=HTTPBasicAuth(inviter['identity'], inviter['password']), headers=headers)
        self.assertEqual(200, resp.status_code, resp.text)
        url = self.live_server_url + '/agent/admin/wallets/%s/pairwise/create_pairwise_statically/' % invitee['wallet_uid']
        pairwise_invitee = dict(
            my_did=did_invitee,
            their_did=did_inviter,
            their_verkey=verkey_inviter,
            metadata={
                'their_endpoint': inviter['endpoint_url'],
                'their_vk': verkey_inviter,
                'my_vk': verkey_invitee,
            }
        )
        resp = requests.post(url, json=pairwise_invitee, auth=HTTPBasicAuth(invitee['identity'], invitee['password']),
                             headers=headers)
        self.assertEqual(200, resp.status_code, resp.text)

        # Step 2: generate invitation link
        url = self.live_server_url + '/agent/admin/wallets/%s/endpoints/%s/invitations/ensure_exists/' % \
              (inviter['wallet_uid'], inviter['endpoint_uid'])
        invitation_kwargs = dict(**cred)
        invitation_kwargs['my_did'] = did_inviter
        invitation_kwargs['seed'] = 'invitation-seed'
        resp = requests.post(url, json=invitation_kwargs, auth=HTTPBasicAuth(inviter['identity'], inviter['password']))
        self.assertEqual(200, resp.status_code, resp.text)
        invite_url_string = resp.json()['url']
        print('Invitation LINK: %s' % invite_url_string)
        # Step 3: send invite to Invitee
        url = self.live_server_url + '/agent/admin/wallets/%s/endpoints/%s/invite/' % \
              (invitee['wallet_uid'], invitee['endpoint_uid'])
        invite = dict(**cred)
        invite['url'] = invite_url_string
        invite['my_did'] = did_invitee
        resp = requests.post(url, json=invite, auth=HTTPBasicAuth(invitee['identity'], invitee['password']))
        self.assertEqual(200, resp.status_code)
        log = resp.json()
        self.assertTrue(log)
        print('======== INVITE LOG =========')
        print(json.dumps(log, indent=2, sort_keys=True))
        print('===============================')

    def test_credential_propose(self):
        actor = dict(
            identity=self.IDENTITY_AGENT1,
            password=self.IDENTITY_PASS,
            wallet_uid=AgentAccount.objects.get(username=self.IDENTITY_AGENT1).wallets.first().uid,
        )
        url = self.live_server_url + '/agent/admin/wallets/%s/proving/propose_credential/' % actor['wallet_uid']

        request = {
            'comment': 'My Comment',
            'locale': 'ru',
            'schema_id': 'some-schema-id',
            'schema_name': 'some-schema-name',
            'schema_version': '1.5',
            'schema_issuer_did': 'some-issuer-did',
            'cred_def_id': 'some-sred-def-id',
            'issuer_did': 'some-issuer-did',
            'proposal_attrib': [
                {
                    'name': 'attrib1',
                    'value': 'value1'
                },
                {
                    'name': 'attrib2',
                    'mime_type': 'image/pmg',
                    'value': base64.b64encode('blablabla'.encode()).decode()
                }
            ],
            'proposal_attrib_translation': [
                {
                    'attrib_name': 'attrib1',
                    'translation': 'Имя'
                },
                {
                    'attrib_name': 'attrib1',
                    'translation': 'Аватар'
                }
            ]
        }

        resp = requests.post(url, json=request, auth=HTTPBasicAuth(actor['identity'], actor['password']))
        self.assertEqual(200, resp.status_code, resp.text)
        message = resp.json()
        self.assertTrue(message)

    def test_issue_feature_0036_0037(self):
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
        trustee_seed = '000000000000000000000000Trustee1'
        did_issuer, verkey_issuer = self.create_did(issuer['wallet'], trustee_seed)
        did_holder, verkey_holder = self.create_did(holder['wallet'])

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

        # Register schemas and cred defs
        schema = {
            'name': 'test_schema_' + uuid.uuid4().hex,
            'version': '1.2',
            'attributes': ["age", "sex", "height", "name"]
        }
        cred_def_id, cred_def_json, cred_def_request, schema = run_async(self.register_schema(
            issuer['wallet'], schema, did_issuer
        ), timeout=30)

        # Issuer: start
        credential = dict(sex='male', name='Alex', height=175, age=28)
        cred_id = 'my-cred-id-' + uuid.uuid4().hex
        data = dict(
            cred_def=cred_def_json,
            cred_def_id=cred_def_id,
            issuer_schema=schema,
            values=credential, comment='My Comment', locale='ru',
            preview={'age': '28'},
            translation={'age': 'Возраст'},
            their_did=did_holder,
            pass_phrase=self.WALLET_PASS_PHRASE,
            cred_id=cred_id
        )
        url = self.live_server_url + '/agent/admin/wallets/%s/messaging/issue_credential/' % issuer['wallet']
        resp = requests.post(url, json=data, auth=HTTPBasicAuth(issuer['account'], issuer['password']))
        self.assertEqual(resp.status_code, 200, resp.text)
        log = resp.json()
        self.assertTrue(log)
        print('------- LOG -----------')
        print(json.dumps(log, indent=2))
        print('------------------------')
        # Stop issuer state machine
        url = self.live_server_url + '/agent/admin/wallets/%s/messaging/stop_issue_credential/' % issuer['wallet']
        data = dict(
            their_did=did_holder,
            pass_phrase=self.WALLET_PASS_PHRASE
        )
        resp = requests.post(url, json=data, auth=HTTPBasicAuth(issuer['account'], issuer['password']))
        self.assertTrue(400 >= resp.status_code < 500, resp.text)
        # Verify Proof OK
        print('------ Verify Proof OK ------')
        proof_request = {
            'nonce': '123432421212',
            'name': 'proof_req_1',
            'version': '0.1',
            'requested_attributes': {
                'attr1_referent': {
                    'name': 'name',
                    "restrictions": {
                        "issuer_did": did_issuer,
                        "schema_id": schema['id']
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
        data = dict(
            translation={'age': 'Возраст', 'name': 'Имя'},
            their_did=did_holder,
            pass_phrase=self.WALLET_PASS_PHRASE,
            proof_request=proof_request
        )
        url = self.live_server_url + '/agent/admin/wallets/%s/messaging/verify_proof/' % issuer['wallet']
        print('>')
        resp = requests.post(url, json=data, auth=HTTPBasicAuth(issuer['account'], issuer['password']))
        print('<')
        self.assertEqual(resp.status_code, 200, resp.text)
        stat = resp.json()
        self.assertTrue(stat.get('success'))
        proof = stat.get('proof')
        print(json.dumps(proof, indent=2, sort_keys=True))
        self.assertEqual('Alex', str(proof['requested_proof']['revealed_attrs']['attr1_referent']['raw']))

    def test_issue_feature_0036_0037_verify_error(self):
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
        trustee_seed = '000000000000000000000000Trustee1'
        did_issuer, verkey_issuer = self.create_did(issuer['wallet'], trustee_seed)
        did_holder, verkey_holder = self.create_did(holder['wallet'])

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

        # Register schemas and cred defs
        schema = {
            'name': 'test_schema_' + uuid.uuid4().hex,
            'version': '1.0',
            'attributes': ["age", "sex", "height", "name"]
        }
        cred_def_id, cred_def_json, cred_def_request, schema = run_async(self.register_schema(
            issuer['wallet'], schema, did_issuer
        ), timeout=30)

        # Issuer: start
        credential = dict(sex='male', name='Alex', height=175, age=28)
        data = dict(
            cred_def=cred_def_json,
            cred_def_id=cred_def_id,
            issuer_schema=schema,
            values=credential, comment='My Comment', locale='ru',
            preview={'age': '28'},
            translation={'age': 'Возраст'},
            their_did=did_holder,
            pass_phrase=self.WALLET_PASS_PHRASE
        )
        url = self.live_server_url + '/agent/admin/wallets/%s/messaging/issue_credential/' % issuer['wallet']
        resp = requests.post(url, json=data, auth=HTTPBasicAuth(issuer['account'], issuer['password']))
        self.assertEqual(resp.status_code, 200, resp.text)
        log = resp.json()
        self.assertTrue(log)
        print('------- LOG -----------')
        print(json.dumps(log, indent=2))
        print('------------------------')
        # Stop issuer state machine
        url = self.live_server_url + '/agent/admin/wallets/%s/messaging/stop_issue_credential/' % issuer['wallet']
        data = dict(
            their_did=did_holder,
            pass_phrase=self.WALLET_PASS_PHRASE
        )
        resp = requests.post(url, json=data, auth=HTTPBasicAuth(issuer['account'], issuer['password']))
        self.assertTrue(400 >= resp.status_code < 500, resp.text)
        # Verify Proof Error
        print('------ Verify Proof Error ------')
        proof_request = {
            'nonce': '123432421212',
            'name': 'proof_req_2',
            'version': '0.1',
            'requested_attributes': {
                'attr1_referent': {
                    'name': 'name',
                    "restrictions": {
                        "issuer_did": did_issuer,
                        "schema_id": schema['id']
                    }
                },
                'attr2_referent': {
                    'name': 'name-invalid'
                }
            }
        }
        data = dict(
            their_did=did_holder,
            pass_phrase=self.WALLET_PASS_PHRASE,
            proof_request=proof_request
        )
        url = self.live_server_url + '/agent/admin/wallets/%s/messaging/verify_proof/' % issuer['wallet']
        print('>')
        resp = requests.post(url, json=data, auth=HTTPBasicAuth(issuer['account'], issuer['password']))
        print('<')
        self.assertEqual(resp.status_code, 200, resp.text)
        stat = resp.json()
        self.assertFalse(stat.get('success'))
