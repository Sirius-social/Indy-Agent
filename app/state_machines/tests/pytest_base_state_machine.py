import pytest

from authentication.models import AgentAccount
from transport.models import Endpoint
from state_machines.models import StateMachine
from state_machines.base import BaseStateMachine


class MachineDescendant(BaseStateMachine):

    def __init__(self, id_: str):
        self._log = list()
        super().__init__(id_)

    async def handle(self, content_type, data):
        self._log.append((content_type, data))


class PersistenceMachine(BaseStateMachine):

    def __init__(self, id_: str):
        super().__init__(id_)
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
    machine = MachineDescendant('machine-id')

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
    machine1 = PersistenceMachine('machine-id')
    machine1.value1 = 'value1'
    machine1.value2 = 2

    # storing only after invoke
    machine2 = PersistenceMachine('machine-id')
    assert machine2.value1 is None
    assert machine2.value2 is None

    await machine1.invoke('any_content_type', 'AnyValue1')
    machine3 = PersistenceMachine('machine-id')
    await machine3.invoke('test3', 'AnyValue2')
    assert machine3.value1 == machine1.value1
    assert machine3.value2 == machine1.value2
