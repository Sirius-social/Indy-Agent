#!/bin/bash
cd /app

echo "Running PyTest"
pytest core/tests/pytest_wallets.py
pytest core/tests/pytest_reqresp.py
pytest core/tests/pytest_channels.py
pytest core/tests/pytest_ledger.py
pytest core/tests/pytest_aries_0094_cross_domain_routing.py
pytest core/tests/pytest_aries_0160_connection_protocol.py
pytest core/tests/pytest_aries_0023_did_exchange.py
pytest state_machines/tests/pytest_base_state_machine.py
pytest tests/pytest_pool_usecases.py

echo "Run Django Tests"
python manage.py test --noinput
export TEST_RUN_ONLY=test_vcx_invitee
python manage.py test tests.test_vcx_compatibility

export TEST_RUN_VCX=on
python manage.py test tests.test_vcx_compatibility.VCXCompatibilityTest.test_vcx_invitee --noinput
python manage.py test tests.test_vcx_compatibility.VCXCompatibilityTest.test_vcx_inviter --noinput

