from urllib.parse import urljoin

from rest_framework.response import Response
from rest_framework import status
from rest_framework import exceptions
from rest_framework import viewsets
from rest_framework.renderers import JSONRenderer
from rest_framework.decorators import action
from django.db import transaction, connection

from core.wallet import *
from core.aries_rfcs.features.feature_0023_did_exchange.feature import DIDExchange as DIDExchangeFeature
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
        elif self.action == 'generate_invite_link':
            return GenerateInviteLinkSerializer
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
            serializer = WalletCreateSerializer(instance=data)
            return Response(data=serializer.data, status=status.HTTP_201_CREATED)

    def destroy(self, request, *args, **kwargs):
        wallet = self.get_object()
        serializer = WalletAccessSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        credentials = serializer.create(serializer.validated_data)
        conn = WalletConnection(agent_name=wallet.uid, pass_phrase=credentials['pass_phrase'])
        try:
            with transaction.atomic():
                wallet.delete()
                if wallet.endpoint:
                    Endpoint.objects.filter(uid=wallet.endpoint.uid).all().delete()
                try:
                    run_async(WalletAgent.close(
                        agent_name=wallet.uid,
                        pass_phrase=credentials['pass_phrase']
                    ), timeout=self.wallet_creation_timeout)
                except BaseWalletException:
                    pass
                try:
                    run_async(conn.delete(), timeout=self.wallet_creation_timeout)
                except BaseWalletException:
                    db_name = WalletConnection.make_wallet_address(wallet.uid)
                    with connection.cursor() as cursor:
                        cursor.execute("DROP DATABASE '%s'" % db_name)
        except BaseWalletException as e:
            raise exceptions.ValidationError(e.error_message)
        else:
            return Response(status=status.HTTP_204_NO_CONTENT)

    @action(methods=['POST'], detail=True)
    def open(self, request, *args, **kwargs):
        wallet = self.get_object()
        serializer = WalletAccessSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        credentials = serializer.create(serializer.validated_data)
        try:
            run_async(WalletAgent.ensure_agent_is_open(agent_name=wallet.uid, pass_phrase=credentials['pass_phrase']))
        except BaseWalletException as e:
            if isinstance(e, AgentTimeOutError):
                logging.exception('Runtime error!')
                raise
            else:
                raise exceptions.ValidationError(e.error_message)
        else:
            return Response(status=status.HTTP_200_OK)

    @action(methods=['POST'], detail=True)
    def close(self, request, *args, **kwargs):
        wallet = self.get_object()
        serializer = WalletAccessSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        credentials = serializer.create(serializer.validated_data)
        try:
            run_async(WalletAgent.close(agent_name=wallet.uid, pass_phrase=credentials['pass_phrase']))
        except BaseWalletException as e:
            if isinstance(e, AgentTimeOutError):
                pass
            else:
                raise exceptions.ValidationError(e.error_message)
        return Response(status=status.HTTP_200_OK)

    @action(methods=['GET'], detail=True)
    def is_open(self, request, *args, **kwargs):
        wallet = self.get_object()
        value = run_async(WalletAgent.is_open(agent_name=wallet.uid))
        return Response(status=status.HTTP_200_OK, data=dict(is_open=value))

    @action(methods=['POST'], detail=True)
    def generate_invite_link(self, request, *args, **kwargs):
        wallet = self.get_object()
        serializer = GenerateInviteLinkSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        entity = serializer.create(serializer.validated_data)
        label = self.request.user.username
        endpoint = self.__to_dict(wallet)['endpoint']
        # FIRE!!!
        url_path = run_async(
            DIDExchangeFeature.generate_invite_link(label, endpoint, wallet.uid, entity['pass_phrase']),
            timeout=10
        )
        entity['invite_link'] = urljoin(endpoint, url_path)
        serializer = GenerateInviteLinkSerializer(instance=entity)
        return Response(data=serializer.data)

    def __to_dict(self, instance: Wallet):
        if instance.endpoint:
            host = self.request.META['HTTP_HOST']
            scheme = 'https' if self.request.is_secure() else 'http'
            endpoint = urljoin('%s://%s' % (scheme, host), instance.endpoint.uid)
        else:
            endpoint = None
        return dict(uid=instance.uid, endpoint=endpoint)
