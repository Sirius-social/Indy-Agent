import json
import uuid
import asyncio
import threading
from time import sleep
from urllib.parse import urljoin

from rest_framework.response import Response
from rest_framework import status
from rest_framework import exceptions
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.renderers import JSONRenderer
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import action
from channels.generic.http import AsyncHttpConsumer
from channels.db import database_sync_to_async
from django.conf import settings
from django.db import transaction

from core.wallet import WalletConnection, WalletAgent, BaseWalletException
from transport.models import Endpoint
from .serializers import *
from .models import Wallet
from .permissions import *
from .sync2async import run_async


class AdminWalletViewSet(viewsets.mixins.RetrieveModelMixin,
                         viewsets.mixins.CreateModelMixin,
                         viewsets.mixins.DestroyModelMixin,
                         viewsets.mixins.ListModelMixin,
                         viewsets.GenericViewSet):
    """Operate with wallets"""
    permission_classes = [IsNonAnonymousUser]
    renderer_classes = [JSONRenderer]
    lookup_field = 'uid'
    queryset = Wallet.objects
    wallet_creation_timeout = settings.INDY['WALLET_SETTINGS']['TIMEOUTS']['CREATE_DELETE']

    def get_queryset(self):
        queryset = super().get_queryset()
        return queryset.filter(owner=self.request.user)

    def get_serializer_class(self):
        if self.action in ['retrieve', 'list']:
            return WalletRetrieveSerializer
        elif self.action in ['open', 'close', 'destroy']:
            return WalletAccessSerializer
        elif self.action == 'create':
            return WalletCreateSerializer
        elif self.action == 'is_open':
            return EmptySerializer
        else:
            raise NotImplemented()

    def list(self, request, *args, **kwargs):
        wallets = self.get_queryset().all()
        serializer = WalletRetrieveSerializer(
            instance=[self.__to_dict(x) for x in wallets],
            many=True
        )
        return Response(data=serializer.data)

    def retrieve(self, request, *args, **kwargs):
        wallet = self.get_object()
        serializer = WalletRetrieveSerializer(instance=self.__to_dict(wallet))
        return Response(data=serializer.data)

    def create(self, request, *args, **kwargs):
        serializer = WalletCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        credentials = serializer.create(serializer.validated_data)
        if Wallet.objects.filter(uid=credentials['uid']).exists():
            raise exceptions.ValidationError("Wallet with same UID already exists")
        conn = WalletConnection(agent_name=credentials['uid'], pass_phrase=credentials['pass_phrase'])
        try:
            with transaction.atomic():
                endpoint = Endpoint.objects.create(uid=uuid.uuid4().hex, owner=request.user)
                wallet = Wallet.objects.create(uid=credentials['uid'], endpoint=endpoint, owner=request.user)
                run_async(conn.create(), timeout=self.wallet_creation_timeout)
        except BaseWalletException as e:
            raise exceptions.ValidationError(e.error_message)
        else:
            data = self.__to_dict(wallet)
            data.update(credentials)
            serializer = WalletCreateSerializer(instance=request.data)
            return Response(data=serializer.data, status=status.HTTP_201_CREATED)

    def destroy(self, request, *args, **kwargs):
        wallet = self.get_object()
        serializer = WalletAccessSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        credentials = serializer.create(serializer.validated_data)
        conn = WalletConnection(agent_name=wallet.uid, pass_phrase=credentials['pass_phrase'])
        try:
            with transaction.atomic():
                if wallet.endpoint:
                    wallet.endpoint.delete()
                wallet.delete()
                run_async(conn.delete(), timeout=self.wallet_creation_timeout)
        except BaseWalletException as e:
            raise exceptions.ValidationError(e.error_message)
        else:
            return Response(status=status.HTTP_204_NO_CONTENT)

    @action(methods=['POST'], detail=True)
    def open(self, request):
        wallet = self.get_object()
        serializer = WalletAccessSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        credentials = serializer.create(serializer.validated_data)
        try:
            run_async(WalletAgent.open(agent_name=wallet.uid, pass_phrase=credentials['pass_phrase']))
        except BaseWalletException as e:
            raise exceptions.ValidationError(e.error_message)
        else:
            return Response(status=status.HTTP_200_OK)

    @action(methods=['POST'], detail=True)
    def close(self, request):
        wallet = self.get_object()
        serializer = WalletAccessSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        credentials = serializer.create(serializer.validated_data)
        try:
            run_async(WalletAgent.close(agent_name=wallet.uid, pass_phrase=credentials['pass_phrase']))
        except BaseWalletException as e:
            raise exceptions.ValidationError(e.error_message)
        else:
            return Response(status=status.HTTP_200_OK)

    @action(methods=['GET'], detail=True)
    def is_open(self, request):
        wallet = self.get_object()
        try:
            value = run_async(WalletAgent.is_open(agent_name=wallet.uid))
        except BaseWalletException as e:
            raise exceptions.ValidationError(e.error_message)
        else:
            return Response(status=status.HTTP_200_OK, data=dict(is_open=value))

    def __to_dict(self, instance: Wallet):
        if instance.endpoint:
            host = self.request.META['HTTP_HOST']
            scheme = 'https' if self.request.is_secure() else 'http'
            endpoint = urljoin('%s://%s' % (scheme, host), instance.endpoint.uid)
        else:
            endpoint = None
        return dict(uid=instance.uid, endpoint=endpoint)
