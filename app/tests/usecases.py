import json
import random
from time import sleep
from ctypes import cdll
from .utils import ProvisionConfig, Invitation, file_ext

from vcx.state import State
from vcx.api.utils import vcx_agent_provision
from vcx.api.connection import Connection
from vcx.api.credential_def import CredentialDef
from vcx.api.issuer_credential import IssuerCredential
from vcx.api.proof import Proof
from vcx.api.schema import Schema
from vcx.api.vcx_init import vcx_init_with_config


async def alice_establish_connection(alice: ProvisionConfig, invitation: Invitation=None):
    payment_plugin = cdll.LoadLibrary('libnullpay' + file_ext())
    payment_plugin.nullpay_init()

    config = await vcx_agent_provision(str(alice))
    config = json.loads(config)
    # Set some additional configuration options specific to alice
    config['institution_name'] = 'alice'
    config['institution_logo_url'] = 'http://robohash.org/456'
    config['genesis_path'] = '/ci/test_local_pool_transactions_genesis'
    config = json.dumps(config, indent=2, sort_keys=True)
    print('======= Alice config ========')
    print(config)
    print('=============================')
    await vcx_init_with_config(config)
    details = str(invitation)
    connection_to_faber = await Connection.create_with_details(invitation.label, details)
    await connection_to_faber.connect('{"use_public_did": true}')
    connection_state = await connection_to_faber.update_state()
    while connection_state != State.Accepted:
        sleep(2)
        await connection_to_faber.update_state()
        connection_state = await connection_to_faber.get_state()
        pass
    return True


async def faber_generate_invitation(faber: ProvisionConfig, connection_name: str):
    payment_plugin = cdll.LoadLibrary('libnullpay' + file_ext())
    payment_plugin.nullpay_init()

    # 1 Provision an agent and wallet, get back configuration details
    config = await vcx_agent_provision(str(faber))
    config = json.loads(config)
    # Set some additional configuration options specific to faber
    config['institution_name'] = 'Faber'
    config['institution_logo_url'] = 'http://robohash.org/234'
    config['genesis_path'] = '/ci/test_local_pool_transactions_genesis'

    # 2 Initialize libvcx with new configuration
    await vcx_init_with_config(json.dumps(config))

    # 5 Create a connection to alice and print out the invite details
    connection = await Connection.create(connection_name)
    await connection.connect('{"use_public_did": true}')
    await connection.update_state()
    details = await connection.invite_details(False)
    print("**invite details**")
    print(json.dumps(details, indent=2, sort_keys=True))
    print("******************")
    return details, connection


async def faber_establish_connection(vcx_connection):
    connection_state = await vcx_connection.get_state()
    while connection_state != State.Accepted:
        sleep(2)
        await vcx_connection.update_state()
        connection_state = await vcx_connection.get_state()
        print('>--------- connection_state -------------')
        print(repr(connection_state))
    return True


async def faber_setup_issuer(faber: ProvisionConfig, connection_name: str):
    payment_plugin = cdll.LoadLibrary('libnullpay' + file_ext())
    payment_plugin.nullpay_init()

    # 1 Provision an agent and wallet, get back configuration details
    config = await vcx_agent_provision(str(faber))
    config = json.loads(config)
    # Set some additional configuration options specific to faber
    config['institution_name'] = 'Faber'
    config['institution_logo_url'] = 'http://robohash.org/234'
    config['genesis_path'] = '/ci/test_local_pool_transactions_genesis'

    # 2 Initialize libvcx with new configuration
    await vcx_init_with_config(json.dumps(config))

    # 5 Create a connection to alice and print out the invite details
    connection = await Connection.create(connection_name)
    await connection.connect('{"use_public_did": true}')
    await connection.update_state()
    details = await connection.invite_details(False)
    print("**invite details**")
    print(json.dumps(details, indent=2, sort_keys=True))
    print("******************")

    # 3 Create a new schema on the ledger
    version = format("%d.%d.%d" % (random.randint(1, 101), random.randint(1, 101), random.randint(1, 101)))
    schema = await Schema.create('schema_uuid', 'degree schema', version, ['email', 'first_name', 'last_name'], 0)
    schema_id = await schema.get_schema_id()

    # 4 Create a new credential definition on the ledger
    cred_def = await CredentialDef.create('credef_uuid', 'degree', schema_id, 0)
    cred_def_handle = cred_def.handle
    return details, connection, schema_id, cred_def_handle


async def faber_issue_credential(connection, cred_def_handle):
    schema_attrs = {
        'email': 'test',
        'first_name': 'DemoName',
        'last_name': 'DemoLastName',
    }

    print("#12 Create an IssuerCredential object using the schema and credential definition")
    credential = await IssuerCredential.create('alice_degree', schema_attrs, cred_def_handle, 'cred', '0')

    print("#13 Issue credential offer to alice")
    await credential.send_offer(connection)
    await credential.update_state()

    print("#14 Poll agency and wait for alice to send a credential request")
    credential_state = await credential.get_state()
    while credential_state != State.RequestReceived:
        sleep(1)
        await credential.update_state()
        credential_state = await credential.get_state()

    print("#17 Issue credential to alice")
    await credential.send_credential(connection)

    print("#18 Wait for alice to accept credential")
    await credential.update_state()
    credential_state = await credential.get_state()
    while credential_state != State.Accepted:
        sleep(1)
        await credential.update_state()
        credential_state = await credential.get_state()
    return True
