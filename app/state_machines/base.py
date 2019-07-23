import asyncio
from abc import ABC

from channels.db import database_sync_to_async

from transport.base import InboundTransport
from authentication.models import AgentAccount
from core import ReadOnlyChannel, WriteOnlyChannel, ReadWriteTimeoutError
from .models import StateMachine as StateMachinePersistent


class MachineIsDie(Exception):
    pass


class BaseStateMachine(ABC):

    def __init__(self, account: AgentAccount, entrypoint: str, nonce: str):
        self.__id = self.make_id(account, entrypoint, nonce)
        self.__inbound = None
        self.__entrypoint = entrypoint
        self.__nonce = nonce
        self.__account = account

    @classmethod
    def make_id(cls, account: AgentAccount, entrypoint: str, nonce: str):
        return 'machine://%s:%s/%s/%s' % (cls.__name__, account.username, entrypoint, nonce)

    @database_sync_to_async
    def load_state(self):
        """Load state from persistent storage"""
        state = StateMachinePersistent.objects.get_or_create(id=self.__id, transport=self.__inbound.descriptor)
        return dict(state.context)

    @database_sync_to_async
    def store_state(self, value: dict):
        """Store state to persistent storage"""
        state = StateMachinePersistent.objects.get_or_create(id=self.__id, transport=self.__inbound.descriptor)
        state.context = value
        state.save()

    @database_sync_to_async
    def get_inbound(self):
        if self.__inbound is None:
            self.__inbound = InboundTransport(self.__entrypoint, self.__nonce)
        return self.__inbound

    @database_sync_to_async
    def update_state(self, **values):
        """Update state to persistent storage"""
        state = StateMachinePersistent.objects.get_or_create(id=self.__id, transport=self.__inbound.descriptor)
        data = state.context
        data.update(dict(**values))
        state.context = data
        state.save()

    @property
    def account(self):
        """Get account who is owner of state machine"""
        return self.__account

    async def routine(self):
        raise NotImplemented('')

    async def __scheduler(self):

        async def alive_pong():
            pings = await ReadOnlyChannel.create(name='pings:%s' % self.__id)
            pongs = await WriteOnlyChannel.create(name='pongs:%s' % self.__id)
            try:
                while True:
                    success, data = pings.read(timeout=None)
                    if success:
                        pongs.broadcast(data)
                    else:
                        await self.terminate()
                        break
            finally:
                await pings.close()
                await pongs.close()

        asyncio.gather(alive_pong(), self.routine())

    async def terminate(self):
        await self.__inbound.close()

    @classmethod
    async def __start_instance(cls, account: AgentAccount, entrypoint: str, nonce: str):
        instance = cls(account, entrypoint, nonce)
        asyncio.ensure_future(instance.__scheduler())

    @classmethod
    async def __ensure_machine_running(cls, account: AgentAccount, entrypoint: str, nonce: str, timeout):
        id_ = cls.make_id(account, entrypoint, nonce)
        pings = await WriteOnlyChannel.create(name='pings:%s' % id_)
        pongs = await ReadOnlyChannel.create(name='pongs:%s' % id_)
        try:
            ping = {'marker': 'ping'}
            success = pings.write(ping)
            if success:
                try:
                    success, pong = pongs.read(timeout=timeout)
                    if success:
                        if ping == pong:
                            return
                        else:
                            raise MachineIsDie()
                    else:
                        raise MachineIsDie()
                except ReadWriteTimeoutError:
                    raise MachineIsDie()
        finally:
            await pongs.close()


class StateMachineAsProcedure(BaseStateMachine):
    pass


class StateMachineAsHandler(BaseStateMachine):

    WAIT_TIMEOUT = None

    def handle(self, content_type, body):
        raise NotImplemented('')

    async def routine(self):
        inbound = await self.get_inbound()
        while True:
            content_type, body = await inbound.wait(self.WAIT_TIMEOUT)
            self.handle(content_type, body)
