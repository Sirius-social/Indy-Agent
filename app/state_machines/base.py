from abc import ABC, abstractmethod

from channels.db import database_sync_to_async

from core.wallet import WalletConnection
from authentication.models import AgentAccount
from .models import StateMachine as StateMachinePersistent


class MachineIsDie(Exception):
    pass


class BaseStateMachine(ABC):

    """State machine is running inside Django-Channel infrastructure"""

    def __init__(self, account: AgentAccount, endpoint: str, name: str):
        account_addr = account.username if account else '<any>'
        self.__id = 'machine://%s:%s/%s/%s' % (self.__class__.__name__, account_addr, endpoint, name)
        self.__account = account
        self.__endpoint = endpoint
        self.__cache = dict()
        self.__wallet = None

    @abstractmethod
    async def handle(self, content_type, data):
        pass

    async def invoke(self, content_type, data, wallet: WalletConnection=None):
        self.__cache = await database_sync_to_async(self.__load_state)()
        self.__wallet = wallet
        await self.handle(content_type, data)
        await database_sync_to_async(self.__store_state)(self.__cache)

    def get_id(self):
        return self.__id

    def get_wallet(self):
        return self.__wallet

    def __load_state(self):
        """Load state from persistent storage"""
        state, _ = StateMachinePersistent.objects.get_or_create(
            id=self.__id, defaults=dict(context={}, endpoint_uid=self.__endpoint)
        )
        return state.context

    def __store_state(self, value: dict):
        """Store state to persistent storage"""
        state, _ = StateMachinePersistent.objects.get_or_create(
            id=self.__id, defaults=dict(context={}, endpoint_uid=self.__endpoint)
        )
        state.context = value
        # update last_access anyway
        state.save()

    def __getattribute__(self, item: str):
        if item.startswith('_') or item in ['invoke', 'handle', 'get_id', 'get_wallet']:
            value = super().__getattribute__(item)
            return value
        else:
            return self.__cache.get(item, None)

    def __setattr__(self, key: str, value):
        if key.startswith('_'):
            super().__setattr__(key, value)
        else:
            self.__cache[key] = value

    def __delattr__(self, item: str):
        if item.startswith('_'):
            super().__delattr__(item)
        else:
            if item in self.__cache:
                del self.__cache[item]
            else:
                raise AttributeError('Attribute "%s" not found' % item)
