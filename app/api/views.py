import json
import asyncio

from rest_framework.response import Response
from rest_framework import status
from rest_framework import viewsets
from rest_framework.renderers import JSONRenderer
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import action
from channels.generic.http import AsyncHttpConsumer
from channels.db import database_sync_to_async

from core.wallet import MultiConnWallet, WalletConnectionException
from .models import Wallet
from .serializers import OpenWalletSerializer, WalletSerializer


class OpenWalletApiView(AsyncHttpConsumer):

    async def handle(self, body):
        await self.send_headers(headers=[
            ("Content-Type".encode("utf-8"), "application/json".encode("utf-8")),
        ])
        account = self.scope["user"]
        serializer = OpenWalletSerializer(data=body)
        if not serializer.is_valid(raise_exception=False):
            await self.send_response(
                status=status.HTTP_400_BAD_REQUEST,
                body=json.dumps(serializer.error_messages).encode("utf-8")
            )
        credentials = serializer.create(serializer.validated_data)
        try:
            agent_name = "%s_%s" % (account.username, credentials['name'])
            await MultiConnWallet.connect(agent_name, credentials['pass_phrase'])
        except WalletConnectionException:
            await self.send_response(status=status.HTTP_400_BAD_REQUEST, body=b"")
        await database_sync_to_async(self.db_create_wallet_and_endpoint)(agent_name)

    @staticmethod
    def db_create_wallet_and_endpoint(owner, name):
        inst, created = Wallet.objects.get_or_create(owner=owner, name=name, defaults=dict(status='opened'))
        if not created:
            inst.status = 'opened'
            inst.save()


class AdminWalletViewSet(viewsets.GenericViewSet):
    """Operate with wallets"""
    # permission_classes = [IsAuthenticated]
    serializer_class = WalletSerializer
    renderer_classes = [JSONRenderer]
    queryset = Wallet.objects.all()
    lookup_field = 'name'

    @action(methods=['GET'], detail=False)
    def test_asyncio(self):
        f = asyncio.ensure_future(self.print())
        return Response()

    async def print(self):
        print('>Enter print')
        asyncio.sleep(1)
        print('> Leave print')