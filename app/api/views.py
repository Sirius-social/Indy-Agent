import json
import asyncio
import threading
from time import sleep

from rest_framework.response import Response
from rest_framework import status
from rest_framework import viewsets
from rest_framework.renderers import JSONRenderer
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import action
from channels.generic.http import AsyncHttpConsumer
from channels.db import database_sync_to_async

from core.wallet import WalletConnectionException
from .serializers import OpenWalletSerializer
from .sync2async import run_async


class OpenWalletApiView(AsyncHttpConsumer):

    async def handle(self, body):
        await self.send_headers(headers=[
            ("Content-Type".encode("utf-8"), "application/json".encode("utf-8")),
        ])
        account = self.scope["user"]
        if account.is_anonymous:
            await self.send_response(status=403, body=b"")
        serializer = OpenWalletSerializer(data=body)
        if not serializer.is_valid(raise_exception=False):
            await self.send_response(
                status=status.HTTP_400_BAD_REQUEST,
                body=json.dumps(serializer.error_messages).encode("utf-8")
            )

        await database_sync_to_async(self.db_create_wallet_and_endpoint)(agent_name)

    @staticmethod
    def db_create_wallet_and_endpoint(owner, name):
        pass


class Executor:

    __instance = None

    def __init__(self):
        if self.__instance is not None:
            raise RuntimeError()
        else:
            def threaded_loop(loop: asyncio.AbstractEventLoop):
                try:
                    asyncio.set_event_loop(loop)
                    loop.run_forever()
                except Executor as e:
                    print(str(e))
                else:
                    pass
            self.loop = asyncio.new_event_loop()
            self.thread = threading.Thread(target=threaded_loop, args=(self.loop,))
            self.thread.daemon = True
            self.thread.start()

    @classmethod
    def get_loop(cls):
        return cls.get_instance().loop

    @classmethod
    def get_instance(cls):
        if not cls.__instance:
            cls.__instance = Executor()
        return cls.__instance


class AdminWalletViewSet(viewsets.GenericViewSet):
    """Operate with wallets"""
    # permission_classes = [IsAuthenticated]
    renderer_classes = [JSONRenderer]
    lookup_field = 'name'

    @action(methods=['GET'], detail=False)
    def test_asyncio(self, request):
        run_async(self.print(1))
        return Response()

    async def print(self, i: int):
        print('>Enter print [%d]' % i)
        await asyncio.sleep(1)
        print('> Leave print [%d]' % i)