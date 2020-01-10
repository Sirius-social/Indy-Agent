import uuid
import logging
import asyncio
import aioredis
from abc import ABC, abstractmethod

import aiohttp
from django.core.cache import caches
from django.conf import settings

from transport.const import *
from core.messages.message import Message


CACHE = caches['state_machines']
FEATURES_REGISTRY = []


def register_feature(cls):
    if cls not in FEATURES_REGISTRY:
        FEATURES_REGISTRY.append(cls)


def load_content_features(mime_type: str):
    features_classes = []
    for cls in FEATURES_REGISTRY:
        if issubclass(cls, ContentFeature) and cls.MIME_TYPE == mime_type:
            features_classes.append(cls)
    return features_classes


class FeatureMeta(type):

    def __new__(mcs, name, bases, class_dict):
        cls = type.__new__(mcs, name, bases, class_dict)
        register_feature(cls)
        return cls


class ContentFeature:

    MIME_TYPE = None

    @abstractmethod
    def parse(self, body: bytes) -> Message:
        """
        :param body:
        :return: Message instance
        """
        pass


class WireMessageFeature:

    @classmethod
    @abstractmethod
    async def handle(cls, agent_name: str, wire_message: bytes, my_label: str=None, my_endpoint: str=None) -> bool:
        """
        :param agent_name: Indy agent name
        :param wire_message: Wired Input message
        :param my_label: Self Indy Label
        :param my_endpoint: Self endpoint
        :return: response message or None
        """
        return False


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

    def __del__(self):
        if not self._is_closed and self.redis:
            self.redis.close()

    @classmethod
    async def create(cls, name, live_timeout=settings.REDIS_CONN_TIMEOUT):
        self = cls()
        self.redis = await aioredis.create_redis(
            'redis://%s' % settings.REDIS_ADDRESS, timeout=live_timeout
        )
        self.name = 'channel://' + name
        self._is_closed = False
        await self._setup()
        return self

    async def close(self):
        if not self._is_closed:
            self._is_closed = True
            self.redis.close()

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
        if not self.is_closed:
            packet = dict(kind='close', body=None)
            await self.redis.publish_json(self.name, packet)
            await super().close()

    async def _setup(self):
        pass


class AsyncReqResp:

    def __init__(self, address: str):
        self.address = address
        self.__listening_chan = None

    async def req(self, data, timeout=settings.REDIS_CONN_TIMEOUT):
        resp_channel_name = uuid.uuid4().hex
        resp_channel = await ReadOnlyChannel.create(resp_channel_name)
        try:
            req_channel = await WriteOnlyChannel.create(self.address)
            packet = dict(
                resp_channel_name=resp_channel_name,
                data=data
            )
            success = await req_channel.write(packet)
            if success:
                try:
                    success, resp_data = await resp_channel.read(timeout)
                except ReadWriteTimeoutError:
                    return False, None
                if success:
                    return True, resp_data
                else:
                    return False, None
            else:
                return False, None
        finally:
            await resp_channel.close()

    async def wait_req(self):
        chan = await self.__get_listening_chan()
        _, packet = await chan.read(timeout=None)
        chan = await WriteOnlyChannel.create(packet['resp_channel_name'])
        data = packet['data']
        return data, chan

    async def start_listening(self):
        await self.__get_listening_chan()

    async def stop_listening(self):
        if self.__listening_chan:
            await self.__listening_chan.close()

    async def __get_listening_chan(self):
        if self.__listening_chan is None:
            self.__listening_chan = await ReadOnlyChannel.create(self.address)
        return self.__listening_chan


class EndpointTransport:

    DEFAULT_WIRE_CONTENT_TYPE = WIRED_CONTENT_TYPES[0]

    def __init__(self, address: str):
        parts = address.split('://')
        if len(parts) != 2:
            raise ValueError('Expected scheme in address: %s' % address)
        self.__address = address
        self.__scheme = parts[0]
        self.__path = parts[1]

    async def send_wire_message(self, wire_message: bytes, content_type=DEFAULT_WIRE_CONTENT_TYPE):
        if self.__scheme in ['http', 'https']:
            async with aiohttp.ClientSession() as session:
                headers = {
                    'content-type': content_type
                }
                async with session.post(self.__address, data=wire_message, headers=headers) as resp:
                    if resp.status != 202:
                        logging.error('Sending problem report to endpoint with error. Resp status: %d' % resp.status)
                        err_message = await resp.text()
                        logging.error(err_message)
                    return resp.status
        elif self.__scheme == 'channel':
            chan = await WriteOnlyChannel.create(self.__path)
            await chan.write([content_type, wire_message.decode()])
