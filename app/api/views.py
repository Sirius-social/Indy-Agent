import json

from rest_framework import status
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
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
            await MultiConnWallet.connect(credentials['name'], credentials['pass_phrase'])
        except WalletConnectionException:
            await self.send_response(status=status.HTTP_400_BAD_REQUEST, body=b"")
        await database_sync_to_async(self.db_create_wallet_and_endpoint)(credentials['name'])

    @staticmethod
    def db_create_wallet_and_endpoint(owner, name):
        inst, created = Wallet.objects.get_or_create(owner=owner, name=name, defaults=dict(status='opened'))
        if not created:
            inst.status = 'opened'
            inst.save()


class AdminViewSet(viewsets.GenericViewSet):
    """Operate with wallets"""
    permission_classes = [IsAuthenticated]
    serializer_class = WalletSerializer
    queryset = Wallet.objects.all()
    lookup_field = 'name'



