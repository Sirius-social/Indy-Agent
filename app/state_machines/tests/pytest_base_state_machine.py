import pytest

from authentication.models import AgentAccount
from transport.models import Endpoint
from state_machines.models import StateMachine
from state_machines.base import BaseStateMachine


class MachineDescendant(BaseStateMachine):

    def __init__(self, account: AgentAccount, entrypoint: str, name: str):
        self._log = list()
        super().__init__(account, entrypoint, name)

    async def handle(self, content_type, data):
        self._log.append((content_type, data))


class PersistenceMachine(BaseStateMachine):

    def __init__(self, account: AgentAccount, entrypoint: str, name: str):
        super().__init__(account, entrypoint, name)
        self.value1 = None
        self.value2 = None

    async def handle(self, content_type, data):
        if self.value1 is None:
            self.value1 = data
        elif self.value2 is None:
            self.value2 = data


@pytest.mark.asyncio
@pytest.mark.django_db
async def test_invoke():
    account = AgentAccount.objects.create(username='test')
    machine = MachineDescendant(account, 'endpoint_test', 'name')

    test_args = ('test_content_type', {'x': 1, 'y': 2})
    await machine.invoke(*test_args)
    assert len(machine._log) == 1
    assert machine._log[0] == test_args
    state1 = StateMachine.objects.filter(id=machine.get_id()).first()
    assert state1 is not None

    await machine.invoke(*test_args)
    assert StateMachine.objects.filter(id=machine.get_id()).count() == 1
    # check access timestamp is updated
    state2 = StateMachine.objects.filter(id=machine.get_id()).first()
    assert state2.last_access > state1.last_access


@pytest.mark.asyncio
@pytest.mark.django_db
async def test_persistence():
    account = AgentAccount.objects.create(username='test')
    endpoint = 'endpoint_test'
    machine_name = 'name'
    machine1 = PersistenceMachine(account, endpoint, machine_name)
    machine1.value1 = 'value1'
    machine1.value2 = 2

    # storing only after invoke
    machine2 = PersistenceMachine(account, endpoint, machine_name)
    assert machine2.value1 is None
    assert machine2.value2 is None

    await machine1.invoke('any_content_type', 'AnyValue1')
    machine3 = PersistenceMachine(account, endpoint, machine_name)
    await machine3.invoke('test3', 'AnyValue2')
    assert machine3.value1 == 'AnyValue1'
    assert machine3.value2 == 'AnyValue2'


@pytest.mark.asyncio
@pytest.mark.django_db
async def test_destroy_machine_on_remove_endpoint():
    account = AgentAccount.objects.create(username='test')
    endpoint = Endpoint.objects.create(uid='unique-uid', owner=account)

    machine1 = MachineDescendant(account, endpoint.uid, 'name1')
    await machine1.invoke('any_content_type', None)
    machine2 = MachineDescendant(account, endpoint.uid, 'name2')
    await machine2.invoke('any_content_type', None)

    assert StateMachine.objects.filter(endpoint_uid=endpoint.uid).count() == 2

    endpoint.delete()
    assert StateMachine.objects.filter(endpoint_uid=endpoint.uid).count() == 0
