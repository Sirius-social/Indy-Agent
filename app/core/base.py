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
            'redis://%s' % settings.REDIS_ADDRESS, timeout=live_timeout
        )
        self.name = 'chan:' + name
        self._is_closed = False
        await self._setup()
        return self

    async def close(self):
        self._is_closed = True

    @property
    def is_closed(self):
        return self._is_closed

    async def _setup(self):
        raise NotImplemented()


class ReadOnlyChannel(CustomChannel):

    def __init__(self):
        super().__init__()
        self.queue = list()

    async def read(self, timeout):
        if self._is_closed:
            raise ChannelIsClosedError()
        try:
            while True:
                await asyncio.wait_for(self.__async_reader(), timeout=timeout)
                packet = self.queue.pop(0)
                if packet['kind'] == 'data':
                    break
                elif packet['kind'] == 'close':
                    await self.close()
                    return False, None
        except asyncio.TimeoutError:
            raise ReadWriteTimeoutError()
        return True, packet['body']

    async def close(self):
        await self.redis.unsubscribe(self.name)
        await super().close()

    async def _setup(self):
        res = await self.redis.subscribe(self.name)
        self.channel = res[0]

    async def __async_reader(self):
        await self.channel.wait_message()
        msg = await self.channel.get_json()
        self.queue.append(msg)


class WriteOnlyChannel(CustomChannel):

    async def write(self, data):
        """Send data to single recipient
        Return: True if single recipient socket is available
        """
        counter = await self.broadcast(data)
        return counter == 1

    async def broadcast(self, data):
        """Send data to multiple recipients
        Return: recipient socket that are available
        """
        if self._is_closed:
            raise ChannelIsClosedError()
        packet = dict(kind='data', body=data)
        result = await self.redis.publish_json(self.name, packet)
        return result

    async def close(self):
        packet = dict(kind='close', body=None)
        await self.redis.publish_json(self.name, packet)
        await super().close()

    async def _setup(self):
        pass
