#!/bin/bash
cd /app

echo "Running PyTesta"
pytest core/tests/pytest_wallets.py
pytest core/tests/pytest_reqresp.py
pytest core/tests/pytest_channels.py
pytest core/tests/pytest_aries_0160_connection_protocol.py
pytest core/tests/pytest_aries_0023_did_exchange.py
pytest state_machines/tests/pytest_base_state_machine.py

echo "Run Django Tests"
python manage.py test --noinput