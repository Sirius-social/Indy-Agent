from urllib.parse import urljoin

from rest_framework.response import Response
from rest_framework import status
from rest_framework import exceptions
from rest_framework import viewsets
from rest_framework.views import APIView
from rest_framework.generics import get_object_or_404
from rest_framework_extensions.mixins import NestedViewSetMixin
from rest_framework.renderers import JSONRenderer, TemplateHTMLRenderer
from rest_framework.decorators import action
from django.db import transaction, connection

from core.wallet import *
from core.permissions import *
from core.sync2async import run_async
from .serializers import *
from .exceptions import *
from .models import Wallet


WALLET_AGENT_TIMEOUT = settings.INDY['WALLET_SETTINGS']['TIMEOUTS']['AGENT_REQUEST']


async def ensure_wallet_exists(name, pass_phrase):
    try:
        conn = WalletConnection(name, pass_phrase)
        await conn.connect()
        await conn.close()
    except Exception as e:
        raise


class MaintenanceViewSet(viewsets.GenericViewSet):
    """Maintenance user sessions"""
    serializer_class = EmptySerializer

    @action(methods=["GET", "POST"], detail=False)
    def check_health(self, request):
        return Response(dict(success=True, message='OK'))

    @action(methods=["GET"], detail=False)
    def version(self, request):
        return Response(settings.VERSION)

    @action(methods=["GET"], detail=False)
    def logout(self, request):
        """Logout for current BasicAuth/Session based session"""
        raise exceptions.NotAuthenticated(detail=_('You are logged out'))


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
        elif self.action in ['create', 'ensure_exists']:
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
                wallet = Wallet.objects.create(uid=credentials['uid'], owner=request.user)
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

    @action(methods=['POST'], detail=False)
    def ensure_exists(self, request, *args, **kwargs):
        serializer = WalletCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        credentials = serializer.create(serializer.validated_data)
        wallet = self.get_queryset().filter(uid=credentials['uid'], owner=request.user).first()
        if wallet is None:
            with transaction.atomic():
                wallet = Wallet.objects.create(uid=credentials['uid'], owner=request.user)
                run_async(
                    ensure_wallet_exists(wallet.uid, credentials['pass_phrase']),
                    timeout=self.wallet_creation_timeout
                )
            return Response(status=status.HTTP_201_CREATED)
        else:
            if wallet.owner_id != request.user.id:
                raise exceptions.PermissionDenied()
            else:
                return Response(status=status.HTTP_200_OK)

    @staticmethod
    def __to_dict(instance: Wallet):
        return dict(uid=instance.uid)


class PairwiseViewSet(NestedViewSetMixin,
                      viewsets.GenericViewSet):
    """Pairwise list discovering"""
    permission_classes = [IsNonAnonymousUser]
    renderer_classes = [JSONRenderer]
    serializer_class = WalletAccessSerializer

    def get_serializer_class(self):
        if self.action == 'get_metadata':
            return DIDAccessSerializer
        else:
            return super().get_serializer_class()

    @action(methods=['POST'], detail=False)
    def all(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        serializer = WalletAccessSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        credentials = serializer.create(serializer.validated_data)
        ret = run_async(
            WalletAgent.list_pairwise(
                agent_name=wallet.uid,
                pass_phrase=credentials['pass_phrase']
            ),
            timeout=WALLET_AGENT_TIMEOUT
        )
        return Response(data=ret)

    @action(methods=['POST'], detail=False)
    def get_metadata(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        serializer = DIDAccessSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        credentials = serializer.create(serializer.validated_data)
        try:
            ret = run_async(
                WalletAgent.get_pairwise(
                    agent_name=wallet.uid,
                    pass_phrase=credentials['pass_phrase'],
                    their_did=credentials['their_did']
                ),
                timeout=WALLET_AGENT_TIMEOUT
            )
        except WalletItemNotFound as e:
            raise exceptions.ValidationError(detail=e.error_message)
        return Response(data=ret)

    def get_wallet(self):
        if 'wallet' in self.get_parents_query_dict():
            wallet_uid = self.get_parents_query_dict()['wallet']
            return get_object_or_404(Wallet.objects, uid=wallet_uid, owner=self.request.user)
        else:
            raise exceptions.NotFound()


class WalletState(APIView):
    template_name = 'wallet_state.html'
    renderer_classes = [TemplateHTMLRenderer]
    permission_classes = [IsNonAnonymousUser]

    def get(self, request):
        context = dict()
        host = request.META['HTTP_HOST']
        schema = 'wss' if request.is_secure() else 'ws'
        context['websocket'] = '%s://%s/agent/ws/wallets/status/' % (schema, host)
        return Response(data=context)


class DIDViewSet(NestedViewSetMixin, viewsets.GenericViewSet):
    """Manage DIDs"""
    permission_classes = [IsNonAnonymousUser]
    renderer_classes = [JSONRenderer]
    serializer_class = WalletAccessSerializer

    def get_serializer_class(self):
        if self.action == 'list_my_dids_with_meta':
            return DIDSerializer
        elif self.action == 'create_and_store_my_did':
            return DIDCreateSerializer
        else:
            return super().get_serializer_class()

    @action(methods=['POST'], detail=False)
    def list_my_dids_with_meta(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        serializer = WalletAccessSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        credentials = serializer.create(serializer.validated_data)
        ret = run_async(
            WalletAgent.list_my_dids_with_meta(
                agent_name=wallet.uid,
                pass_phrase=credentials['pass_phrase']
            ),
            timeout=WALLET_AGENT_TIMEOUT
        )
        return Response(data=ret)

    @action(methods=['POST'], detail=False)
    def create_and_store_my_did(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        serializer = DIDCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        entity = serializer.create(serializer.validated_data)
        try:
            did, verkey = run_async(
                WalletAgent.create_and_store_my_did(
                    agent_name=wallet.uid,
                    pass_phrase=entity['pass_phrase'],
                    seed=entity.get('seed')
                ),
                timeout=WALLET_AGENT_TIMEOUT
            )
        except WalletOperationError as e:
            if 'already exists' in e.error_message.lower():
                return Response(data=dict(detail=e.error_message), status=status.HTTP_409_CONFLICT)
            else:
                raise exceptions.ValidationError(detail=str(e))
        else:
            entity['did'] = did
            entity['verkey'] = verkey
            return Response(data=entity, status=status.HTTP_201_CREATED)

    def get_wallet(self):
        if 'wallet' in self.get_parents_query_dict():
            wallet_uid = self.get_parents_query_dict()['wallet']
            return get_object_or_404(Wallet.objects, uid=wallet_uid, owner=self.request.user)
        else:
            raise exceptions.NotFound()


class LedgerViewSet(NestedViewSetMixin, viewsets.GenericViewSet):
    """Manage Schemas, Credentials, etc"""
    permission_classes = [IsNonAnonymousUser]
    renderer_classes = [JSONRenderer]
    serializer_class = WalletAccessSerializer

    def get_serializer_class(self):
        if self.action == 'nym_request':
            return NymRequestSerializer
        elif self.action == 'register_schema':
            return SchemaRegisterSerializer
        else:
            return super().get_serializer_class()

    @action(methods=['POST'], detail=False)
    def nym_request(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        self_did = self.get_self_did()
        serializer = NymRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        entity = serializer.create(serializer.validated_data)
        try:
            nym_request = run_async(
                WalletAgent.build_nym_request(
                    agent_name=wallet.uid,
                    pass_phrase=entity['pass_phrase'],
                    self_did=self_did,
                    target_did=entity['target_did'],
                    ver_key=entity['ver_key'],
                    role=entity['role'],
                    alias=entity['alias']
                ),
                timeout=WALLET_AGENT_TIMEOUT
            )
            nym_response = run_async(
                WalletAgent.sign_and_submit_request(
                    agent_name=wallet.uid,
                    pass_phrase=entity['pass_phrase'],
                    self_did=self_did,
                    request_json=nym_request
                ),
                timeout=WALLET_AGENT_TIMEOUT
            )
            if nym_response['op'] != 'REPLY':
                reason = nym_response.get('reason')
                raise exceptions.ValidationError(detail=reason)
        except WalletOperationError as e:
            raise exceptions.ValidationError(detail=str(e))
        else:
            return Response(data=dict(
                request=nym_request,
                response=nym_response
            ))

    @action(methods=['POST'], detail=False)
    def register_schema(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        self_did = self.get_self_did()
        serializer = SchemaRegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        entity = serializer.create(serializer.validated_data)
        try:
            schema_request = run_async(
                WalletAgent.build_schema_request(
                    agent_name=wallet.uid,
                    pass_phrase=entity['pass_phrase'],
                    self_did=self_did,
                    name=entity['name'],
                    version=entity['version'],
                    attributes=entity['attributes']
                ),
                timeout=WALLET_AGENT_TIMEOUT
            )
            schema_response = run_async(
                WalletAgent.sign_and_submit_request(
                    agent_name=wallet.uid,
                    pass_phrase=entity['pass_phrase'],
                    self_did=self_did,
                    request_json=schema_request
                ),
                timeout=WALLET_AGENT_TIMEOUT
            )
            if schema_response['op'] == 'REJECT':
                reason = schema_response.get('reason')
                raise ConflictError()
            elif schema_response['op'] != 'REPLY':
                reason = schema_response.get('reason')
                raise exceptions.ValidationError(detail=reason)
        except WalletOperationError as e:
            raise exceptions.ValidationError(detail=str(e))
        return Response(
            status=status.HTTP_201_CREATED,
            data=dict(
                request=schema_request,
                response=schema_response
            ))

    def get_self_did(self):
        if 'self_did' in self.get_parents_query_dict():
            self_did = self.get_parents_query_dict()['self_did']
            return self_did
        else:
            raise exceptions.NotFound()

    def get_wallet(self):
        if 'wallet' in self.get_parents_query_dict():
            wallet_uid = self.get_parents_query_dict()['wallet']
            return get_object_or_404(Wallet.objects, uid=wallet_uid, owner=self.request.user)
        else:
            raise exceptions.NotFound()
