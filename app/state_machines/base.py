import asyncio
import aioredis
from abc import ABC

from django.core.cache import caches
from django.conf import settings


CACHE = caches['state_machines']


class ChannelIsClosedError(Exception):
    pass


class ReadWriteTimeoutError(Exception):
    pass


class CustomChannel(ABC):

    def __init__(self):
        self.redis = None
        self.name = None
        self.channel = None
        self._is_closed = True

    @classmethod
    async def create(cls, name, live_timeout=settings.REDIS_CONN_TIMEOUT):
        self = cls()
        self.redis = await aioredis.create_redis(
            f'redis://{settings.REDIS_ADDRESS}', timeout=live_timeout
        )
        self.name = 'chan:' + name
        self._is_closed = False
        await self._setup()
        return self

    async def close(self):
        self.redis.close()
        self._is_closed = True

    async def _setup(self):
        raise NotImplemented()


class ReadOnlyChannel(CustomChannel):

    def __init__(self):
        super().__init__()
        self.queue = list()

    async def read(self, timeout):
        if self.queue:
            return self.queue.pop(0)
        if self._is_closed:
            raise ChannelIsClosedError()
        try:
            await asyncio.wait_for(self.__async_reader(), timeout=timeout)
        except asyncio.TimeoutError:
            raise ReadWriteTimeoutError()
        return self.queue.pop(0)

    async def close(self):
        await self.redis.unsubscribe(self.name)
        super().close()

    async def _setup(self):
        res = await self.redis.subscribe(self.name)
        self.channel = res[0]

    async def __async_reader(self):
        await self.channel.wait_message()
        msg = await self.channel.get_json()
        self.queue.append(msg)


class WriteOnlyChannel(CustomChannel):

    async def write(self, data):
        if self._is_closed:
            raise ChannelIsClosedError()
        res = await self.redis.publish_json(self.name, data)
        return res == 1
