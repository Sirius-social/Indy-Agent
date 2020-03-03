import uuid
import asyncio

import pytest
from django.db import connection
from channels.db import database_sync_to_async

from core.wallet import WalletConnection, WalletAgent
from core.base import ReadOnlyChannel, WriteOnlyChannel
from core.aries_rfcs.features.feature_0036_issue_credential.feature import *
from core.aries_rfcs.features.feature_0036_issue_credential.statuses import *
from core.indy_sdk_utils import *
from state_machines.base import MachineIsDone


def remove_agent_databases(*names):
    with connection.cursor() as cursor:
        for name in names:
            db_name = WalletConnection.make_wallet_address(name)
            cursor.execute("DROP DATABASE  IF EXISTS %s" % db_name)


@pytest.mark.asyncio
@pytest.mark.django_db
async def test_state_machines():
    await database_sync_to_async(remove_agent_databases)('issuer', 'holder')
    issuer_wallet = WalletConnection('issuer', 'pass')
    holder_wallet = WalletConnection('holder', 'pass')
    issuer_endpoint = await ReadOnlyChannel.create('issuer')
    holder_endpoint = await ReadOnlyChannel.create('holder')

    schema = {
        'name': 'test_schema_' + uuid.uuid4().hex,
        'version': '1.0',
        'attributes': ["age", "sex", "height", "name"]
    }

    await issuer_wallet.create()
    await holder_wallet.create()
    try:
        await issuer_wallet.open()
        await holder_wallet.open()
        try:
            trustee_seed = '000000000000000000000000Trustee1'
            # step 1: create did
            did_issuer, verkey_issuer = await create_and_store_my_did(issuer_wallet, trustee_seed)
            did_holder, verkey_holder = await create_and_store_my_did(holder_wallet)
            # step 2: register schema + cred_def
            schema_request, schema_json = await issuer_wallet.build_schema_request(
                did_issuer, schema['name'], schema['version'], schema['attributes']
            )
            schema_response = await issuer_wallet.sign_and_submit_request(
                did_issuer, schema_request
            )
            assert schema_response['op'] == 'REPLY'

            cred_def_id, cred_def_json, cred_def_request, schema = await issuer_wallet.issuer_create_credential_def(
                did_issuer, schema_json['id'], 'TAG', False
            )
            pass
            # step 3: pairwise exchange
            metadata = {
                'label': 'Holder',
                'their_endpoint': holder_endpoint.name,
                'their_vk': verkey_holder,
                'my_vk': verkey_issuer,
            }
            await store_their_did(issuer_wallet, did_holder, verkey_holder)
            await issuer_wallet.create_pairwise(did_holder, did_issuer, metadata)
            metadata = {
                'label': 'Issuer',
                'their_endpoint': issuer_endpoint.name,
                'their_vk': verkey_issuer,
                'my_vk': verkey_holder,
            }
            await store_their_did(holder_wallet, did_issuer, verkey_issuer)
            await holder_wallet.create_pairwise(did_issuer, did_holder, metadata)
            # State Machines
            issuer_state_machine = IssueCredentialProtocol.IssuerStateMachine('issuer_state_machine')
            credential = dict(sex='male', name='Alex', height=175, age=28)
            issuer_state_machine.to = did_holder
            issuer_state_machine.cred_def_id = cred_def_id
            issuer_state_machine.rev_reg_id = None
            issuer_state_machine.log_channel_name = 'xxx'

            holder_state_machine = IssueCredentialProtocol.HolderSateMachine('holder_state_machine')

            # Issuer start process
            data = dict(
                command=IssueCredentialProtocol.CMD_START,
                cred_def=cred_def_json,
                values=credential, comment='My Comment', locale='ru',
                preview=[{'name': 'age', 'value': '28'}],
                translation=[{'attrib_name': 'age', 'translation': 'Возраст'}]
            )

            await issuer_state_machine.invoke(
                IssueCredentialProtocol.MESSAGE_CONTENT_TYPE, data, issuer_wallet
            )
            success, data = await holder_endpoint.read(timeout=10)
            assert success is True
            content_type, wire_message = data
            wire_message = wire_message.encode()
            assert content_type == EndpointTransport.DEFAULT_WIRE_CONTENT_TYPE
            # Holder receive offer
            await holder_state_machine.invoke(
                content_type, wire_message, holder_wallet
            )
            success, data = await issuer_endpoint.read(timeout=10)
            assert success is True
            content_type, wire_message = data
            wire_message = wire_message.encode()
            assert content_type == EndpointTransport.DEFAULT_WIRE_CONTENT_TYPE
            # Issuer issue credential
            await issuer_state_machine.invoke(
                content_type, wire_message, issuer_wallet
            )
            success, data = await holder_endpoint.read(timeout=10)
            assert success is True
            content_type, wire_message = data
            wire_message = wire_message.encode()
            assert content_type == EndpointTransport.DEFAULT_WIRE_CONTENT_TYPE
            # Holder ack
            try:
                await holder_state_machine.invoke(
                    content_type, wire_message, holder_wallet
                )
            except MachineIsDone:
                pass
            else:
                raise RuntimeError('Unexpected termination')
            success, data = await issuer_endpoint.read(timeout=10)
            assert success is True
            content_type, wire_message = data
            wire_message = wire_message.encode()
            # Issuer recv ack
            try:
                await issuer_state_machine.invoke(
                    content_type, wire_message, issuer_wallet
                )
            except MachineIsDone:
                pass
            else:
                raise RuntimeError('Unexpected termination')
        finally:
            await issuer_wallet.close()
            await holder_wallet.close()

    finally:
        await issuer_wallet.delete()
        await holder_wallet.delete()
