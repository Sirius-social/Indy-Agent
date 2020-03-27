import uuid
import asyncio

import pytest
from django.db import connection
from channels.db import database_sync_to_async

import core.codec
from core.base import ReadOnlyChannel
from core.aries_rfcs.features.feature_0037_present_proof.feature import *
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
    values = dict(sex='male', name='Alex', height=175, age=28)

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
            # step 4: issue credential
            link_secret_name = 'link_secret_name'
            cred_offer = await issuer_wallet.issuer_create_credential_offer(cred_def_id)
            await holder_wallet.prover_create_master_secret(link_secret_name)
            cred_request, cred_request_metadata = await holder_wallet.prover_create_credential_req(
                prover_did=did_holder,
                cred_offer=cred_offer,
                cred_def=cred_def_json,
                master_secret_id=link_secret_name
            )
            encoded_cred_values = dict()
            for key, value in values.items():
                encoded_cred_values[key] = dict(raw=str(value), encoded=core.codec.encode(value))
            ret = await issuer_wallet.issuer_create_credential(
                cred_offer=cred_offer,
                cred_req=cred_request,
                cred_values=encoded_cred_values,
                rev_reg_id=None,
                blob_storage_reader_handle=None
            )
            cred, cred_revoc_id, revoc_reg_delta = ret
            cred_id = await holder_wallet.prover_store_credential(
                cred_req_metadata=cred_request_metadata,
                cred=cred,
                cred_def=cred_def_json,
                rev_reg_def=None,
            )

            # State Machines
            verifier_state_machine = PresentProofProtocol.VerifierStateMachine('verifier_state_machine')
            verifier_state_machine.to = did_holder
            verifier_state_machine.log_channel_name = 'xxx'
            prover_state_machine = PresentProofProtocol.ProverStateMachine('prover_state_machine')
            verifier_wallet = issuer_wallet
            prover_wallet = holder_wallet
            proof_request = {
                'nonce': '123432421212',
                'name': 'proof_req_1',
                'version': '0.1',
                'requested_attributes': {
                    'attr1_referent': {
                        'name': 'name',
                        "restrictions": {
                            "issuer_did": did_issuer,
                            "schema_id": schema_json['id']
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
                command=PresentProofProtocol.CMD_START,
                comment='Some comment',
                proof_request=proof_request,
                translation=[
                    {'attrib_name': 'name', 'translation': 'Имя'}, {'attrib_name': 'age', 'translation': 'Возраст'}
                ]
            )
            await verifier_state_machine.invoke(
                PresentProofProtocol.MESSAGE_CONTENT_TYPE, data, verifier_wallet
            )
            success, data = await holder_endpoint.read(timeout=10)
            assert success is True
            content_type, wire_message = data
            wire_message = wire_message.encode()
            assert content_type == EndpointTransport.DEFAULT_WIRE_CONTENT_TYPE
            # Prover receive request
            await prover_state_machine.invoke(
                content_type, wire_message, holder_wallet
            )
            success, data = await issuer_endpoint.read(timeout=100)
            assert success is True
            content_type, wire_message = data
            wire_message = wire_message.encode()
            pass
        finally:
            await issuer_wallet.close()
            await holder_wallet.close()

    finally:
        await issuer_wallet.delete()
        await holder_wallet.delete()
