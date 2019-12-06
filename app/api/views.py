import json

from django.utils.translation import ugettext_lazy as _
from rest_framework.response import Response
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
from core.ledger import *
from core.codec import encode
from core.sync2async import run_async
from core.proofs import *
from .serializers import *
from .exceptions import *
from .models import *


WALLET_AGENT_TIMEOUT = settings.INDY['WALLET_SETTINGS']['TIMEOUTS']['AGENT_REQUEST']
LEDGER_READ_TIMEOUT = settings.INDY['LEDGER']['TIMEOUTS']['READ']


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
                raise AgentTimeoutError()
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
        elif self.action == 'create_pairwise':
            return CreatePairwiseSerializer
        else:
            return super().get_serializer_class()

    @action(methods=['POST'], detail=False)
    def all(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        serializer = WalletAccessSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        credentials = serializer.create(serializer.validated_data)
        try:
            ret = run_async(
                WalletAgent.list_pairwise(
                    agent_name=wallet.uid,
                    pass_phrase=credentials['pass_phrase']
                ),
                timeout=WALLET_AGENT_TIMEOUT
            )
        except AgentTimeOutError:
            raise AgentTimeoutError()
        else:
            return Response(data=ret)

    @action(methods=['POST'], detail=False)
    def create_pairwise(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        serializer = CreatePairwiseSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        credentials = serializer.create(serializer.validated_data)
        try:
            ret = run_async(
                WalletAgent.create_pairwise(
                    agent_name=wallet.uid,
                    pass_phrase=credentials['pass_phrase'],
                    their_did=credentials['their_did'],
                    my_did=credentials['my_did'],
                    metadata=credentials['metadata']
                ),
                timeout=WALLET_AGENT_TIMEOUT
            )
        except AgentTimeOutError:
            raise AgentTimeoutError()
        else:
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
        except AgentTimeOutError:
            raise AgentTimeoutError()
        else:
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
            return WalletAccessSerializer
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
        except AgentTimeOutError:
            raise AgentTimeoutError()
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
    serializer_class = EmptySerializer

    def get_serializer_class(self):
        if self.action == 'nym_request':
            return NymRequestSerializer
        elif self.action == 'register_schema':
            return SchemaRegisterSerializer
        elif self.action == 'schemas':
            return EmptySerializer
        elif self.action == 'retrieve_did':
            return DIDRetrieveSerializer
        elif self.action == 'get_attribute':
            return GetAttributeSerializer
        elif self.action == 'set_attribute':
            return SetAttributeSerializer
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
        except AgentTimeOutError:
            raise AgentTimeoutError()
        else:
            return Response(data=dict(
                request=nym_request,
                response=nym_response
            ))

    @action(methods=['POST'], detail=False)
    def retrieve_did(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        self_did = self.get_self_did()
        serializer = DIDRetrieveSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        entity = serializer.create(serializer.validated_data)
        try:
            get_nym_request = run_async(
                WalletAgent.build_get_nym_request(
                    agent_name=wallet.uid,
                    pass_phrase=entity['pass_phrase'],
                    self_did=self_did,
                    target_did=entity['did']
                ),
                timeout=WALLET_AGENT_TIMEOUT
            )
            get_nym_response = run_async(
                WalletAgent.sign_and_submit_request(
                    agent_name=wallet.uid,
                    pass_phrase=entity['pass_phrase'],
                    self_did=self_did,
                    request_json=get_nym_request
                ),
                timeout=WALLET_AGENT_TIMEOUT
            )
            if get_nym_response['op'] != 'REPLY':
                reason = get_nym_response.get('reason')
                raise exceptions.ValidationError(detail=reason)
        except WalletOperationError as e:
            raise exceptions.ValidationError(detail=str(e))
        except AgentTimeOutError:
            raise AgentTimeoutError()
        else:
            response = get_nym_response.get('result', {})
            if response:
                data = response['data']
                if type(data) is str:
                    response['data'] = json.loads(data)
            return Response(data=response)

    @action(methods=['POST'], detail=False)
    def register_schema(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        self_did = self.get_self_did()
        serializer = SchemaRegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        entity = serializer.create(serializer.validated_data)

        def ensure_schema_def_exists(schema_json_, ):
            SchemaDefinition.objects.get_or_create(
                defaults=dict(json=json.dumps(schema_json_), did=self_did),
                schema_id=schema_json_['id'], wallet=wallet
            )

        try:
            schema_request, schema_json = run_async(
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
                ensure_schema_def_exists(schema_json)
                raise ConflictError()
            elif schema_response['op'] != 'REPLY':
                reason = schema_response.get('reason')
                raise exceptions.ValidationError(detail=reason)
        except WalletOperationError as e:
            raise exceptions.ValidationError(detail=str(e))
        except AgentTimeOutError:
            raise AgentTimeoutError()
        else:
            ensure_schema_def_exists(schema_json)
            return Response(
                status=status.HTTP_201_CREATED,
                data=dict(
                    request=schema_request,
                    response=schema_response,
                    schema=schema_json,
                    schema_id=schema_json['id']
                ))

    @action(methods=['GET'], detail=False)
    def schemas(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        self_did = self.get_self_did()
        collection = [json.loads(x.json) for x in SchemaDefinition.objects.filter(did=self_did, wallet=wallet).all()]
        return Response(data=collection)

    @action(methods=['POST'], detail=False)
    def get_attribute(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        self_did = self.get_self_did()
        serializer = GetAttributeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        entity = serializer.create(serializer.validated_data)
        name = entity['name']
        try:
            request = run_async(
                WalletAgent.build_get_attrib_request(
                    agent_name=wallet.uid,
                    pass_phrase=entity['pass_phrase'],
                    self_did=self_did,
                    target_did=entity['target_did'],
                    raw=entity['name']
                ),
                timeout=WALLET_AGENT_TIMEOUT
            )
            response = run_async(
                WalletAgent.sign_and_submit_request(
                    agent_name=wallet.uid,
                    pass_phrase=entity['pass_phrase'],
                    self_did=self_did,
                    request_json=request
                ),
                timeout=WALLET_AGENT_TIMEOUT
            )
            if response['op'] != 'REPLY':
                reason = response.get('reason')
                raise exceptions.ValidationError(detail=reason)
        except WalletOperationError as e:
            raise exceptions.ValidationError(detail=str(e))
        except AgentTimeOutError:
            raise AgentTimeoutError()
        else:
            data_str = response['result']['data']
            data = json.loads(data_str)
            return Response(data=data[name])

    @action(methods=['POST'], detail=False)
    def set_attribute(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        self_did = self.get_self_did()
        serializer = SetAttributeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        entity = serializer.create(serializer.validated_data)
        try:
            name = entity['name']
            value = entity['value']
            raw = {name: value}
            request = run_async(
                WalletAgent.build_attrib_request(
                    agent_name=wallet.uid,
                    pass_phrase=entity['pass_phrase'],
                    self_did=self_did,
                    target_did=entity['target_did'],
                    raw=raw
                ),
                timeout=WALLET_AGENT_TIMEOUT
            )
            response = run_async(
                WalletAgent.sign_and_submit_request(
                    agent_name=wallet.uid,
                    pass_phrase=entity['pass_phrase'],
                    self_did=self_did,
                    request_json=request
                ),
                timeout=WALLET_AGENT_TIMEOUT
            )
            if response['op'] != 'REPLY':
                reason = response.get('reason')
                raise exceptions.ValidationError(detail=reason)
        except WalletOperationError as e:
            raise exceptions.ValidationError(detail=str(e))
        except AgentTimeOutError:
            raise AgentTimeoutError()
        else:
            return Response(
                data=dict(
                    request=request,
                    response=response,
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


class MessagingViewSet(NestedViewSetMixin, viewsets.GenericViewSet):
    permission_classes = [IsNonAnonymousUser]
    renderer_classes = [JSONRenderer]
    serializer_class = WalletAccessSerializer

    def get_serializer_class(self):
        if self.action == 'anon_crypt':
            return AnonCryptSerializer
        elif self.action == 'unpack':
            return DecryptSerializer
        elif self.action == 'auth_crypt':
            return AuthCryptSerializer
        else:
            return super().get_serializer_class()

    @action(methods=['POST'], detail=False)
    def auth_crypt(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        serializer = AuthCryptSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        entity = serializer.create(serializer.validated_data)
        try:
            encrypted = run_async(
                WalletAgent.pack_message(
                    agent_name=wallet.uid,
                    message=entity['message'],
                    their_ver_key=entity['their_verkey'],
                    my_ver_key=entity['my_verkey']
                ),
                timeout=WALLET_AGENT_TIMEOUT
            )
        except Exception as e:
            raise ValidationError(detail=str(e))
        else:
            return Response(data=json.loads(encrypted.decode('utf-8')))

    @action(methods=['POST'], detail=False)
    def anon_crypt(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        serializer = AnonCryptSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        entity = serializer.create(serializer.validated_data)
        try:
            encrypted = run_async(
                WalletAgent.pack_message(
                    agent_name=wallet.uid,
                    message=entity['message'],
                    their_ver_key=entity['their_verkey']
                ),
                timeout=WALLET_AGENT_TIMEOUT
            )
        except Exception as e:
            raise ValidationError(detail=str(e))
        else:
            return Response(data=json.loads(encrypted.decode('utf-8')))

    @action(methods=['POST'], detail=False)
    def unpack(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        serializer = DecryptSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        entity = serializer.create(serializer.validated_data)
        try:
            wire_message = json.dumps(entity).encode('utf-8')
            decrypted = run_async(
                WalletAgent.unpack_message(
                    agent_name=wallet.uid,
                    wire_msg_bytes=wire_message,
                ),
                timeout=WALLET_AGENT_TIMEOUT
            )
        except Exception as e:
            raise ValidationError(detail=str(e))
        else:
            decrypted['message'] = json.loads(decrypted['message'])
            return Response(data=decrypted)

    def get_wallet(self):
        if 'wallet' in self.get_parents_query_dict():
            wallet_uid = self.get_parents_query_dict()['wallet']
            return get_object_or_404(Wallet.objects, uid=wallet_uid, owner=self.request.user)
        else:
            raise exceptions.NotFound()


class LedgerReadOnlyViewSet(NestedViewSetMixin, viewsets.GenericViewSet):
    """Manage Schemas, Credentials, etc"""
    permission_classes = [IsNonAnonymousUser]
    renderer_classes = [JSONRenderer]
    serializer_class = LedgerReadSerializer

    def get_serializer_class(self):
        if self.action in ['prover_get_entities', 'verifier_get_entities']:
            return ReadEntitiesSerializer
        else:
            return super().get_serializer_class()

    @action(methods=['POST'], detail=False)
    def prover_get_entities(self, request, *args, **kwargs):
        serializer = ReadEntitiesSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        params = serializer.create(serializer.validated_data)
        try:
            schemas, cred_defs, rev_states = run_async(
                prover_get_entities_from_ledger(
                    did=params['submitter_did'],
                    identifiers=params['identifiers']
                ),
                timeout=LEDGER_READ_TIMEOUT
            )
        except Exception as e:
            raise ValidationError(detail=str(e))
        else:
            return Response(
                dict(schemas=schemas, cred_defs=cred_defs, rev_states=rev_states)
            )

    @action(methods=['POST'], detail=False)
    def verifier_get_entities(self, request, *args, **kwargs):
        serializer = ReadEntitiesSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        params = serializer.create(serializer.validated_data)
        try:
            schemas, cred_defs, rev_reg_defs, rev_regs = run_async(
                verifier_get_entities_from_ledger(
                    did=params['submitter_did'],
                    identifiers=params['identifiers']
                ),
                timeout=LEDGER_READ_TIMEOUT
            )
        except Exception as e:
            raise ValidationError(detail=str(e))
        else:
            return Response(
                dict(schemas=schemas, cred_defs=cred_defs, rev_reg_defs=rev_reg_defs, rev_regs=rev_regs)
            )


class CredDefViewSet(NestedViewSetMixin, viewsets.GenericViewSet):
    """Manage Credential definitions"""
    permission_classes = [IsNonAnonymousUser]
    renderer_classes = [JSONRenderer]
    serializer_class = EmptySerializer

    def get_serializer_class(self):
        if self.action == 'create_and_send':
            return CredentialDefinitionCreateSerializer
        else:
            return super().get_serializer_class()

    @action(methods=['POST'], detail=False)
    def create_and_send(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        self_did = self.get_self_did()
        serializer = CredentialDefinitionCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        entity = serializer.create(serializer.validated_data)
        try:
            try:
                cred_def_id, cred_def_json, cred_def_request, schema = run_async(
                    WalletAgent.issuer_create_credential_def(
                        agent_name=wallet.uid,
                        pass_phrase=entity['pass_phrase'],
                        self_did=self_did,
                        schema_id=entity['schema_id'],
                        tag=entity['tag'],
                        support_revocation=entity['support_revocation'],
                        timeout=settings.INDY['WALLET_SETTINGS']['TIMEOUTS']['CRED_DEF_STORE']
                    ),
                    timeout=settings.INDY['WALLET_SETTINGS']['TIMEOUTS']['CRED_DEF_STORE']
                )
            except WalletOperationError as e:
                if 'already exists' in e.error_message.lower():
                    raise ConflictError()
                else:
                    raise exceptions.ValidationError(detail=str(e))
            else:
                cred_def_model = CredentialDefinition.objects.create(
                    did=self_did, wallet=wallet, cred_def_id=cred_def_id, cred_def_request=json.dumps(cred_def_request),
                    cred_def_json=json.dumps(cred_def_json), schema=json.dumps(schema), schema_id=entity['schema_id']
                )
            if cred_def_model:
                cred_def_id = cred_def_model.cred_def_id
                cred_def_json = json.loads(cred_def_model.cred_def_json)
                cred_def_request = json.loads(cred_def_model.cred_def_request)
                cred_def_response = run_async(
                    WalletAgent.sign_and_submit_request(
                        agent_name=wallet.uid,
                        pass_phrase=entity['pass_phrase'],
                        self_did=self_did,
                        request_json=cred_def_request
                    ),
                    timeout=WALLET_AGENT_TIMEOUT
                )
                if cred_def_response['op'] != 'REPLY':
                    raise exceptions.ValidationError(detail=cred_def_response.get('reason'))
            else:
                raise ValidationError(detail='Unexpected behaviour')
        except AgentTimeOutError:
            raise AgentTimeoutError()
        else:
            return Response(
                status=status.HTTP_201_CREATED,
                data=dict(
                    id=cred_def_id,
                    cred_def=cred_def_json,
                    cred_def_request=cred_def_request,
                    cred_def_response=cred_def_response
                )
            )

    @action(methods=['GET'], detail=False)
    def all(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        self_did = self.get_self_did()
        collection = [
            dict(
                id=x.cred_def_id,
                cred_def=json.loads(x.cred_def_json),
                schema=json.loads(x.schema)
            )
            for x in CredentialDefinition.objects.filter(wallet=wallet, did=self_did).all()
        ]
        return Response(data=collection)

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


class ProvingViewSet(NestedViewSetMixin, viewsets.GenericViewSet):
    """Proving"""
    permission_classes = [IsNonAnonymousUser]
    renderer_classes = [JSONRenderer]
    serializer_class = EmptySerializer

    def get_serializer_class(self):
        if self.action == 'issuer_create_credential_offer':
            return CreateIssuerCredentialOfferSerializer
        elif self.action == 'prover_create_credential_req':
            return CreateProverCredentialRequestSerializer
        elif self.action == 'prover_create_master_secret':
            return CreateProverMasterSecretSerializer
        elif self.action == 'issuer_create_credential':
            return CreateIssuerCredentialSerializer
        elif self.action == 'prover_store_credential':
            return StoreProverCredentialSerializer
        elif self.action == 'prover_search_credentials_for_proof_req':
            return ProofRequestSerializer
        elif self.action == 'prover_close_credentials_search_for_proof_req':
            return CloseSearchHandleSerializer
        elif self.action == 'prover_fetch_credentials_for_proof_req':
            return FetchCredForProofRequestSerializer
        elif self.action == 'prover_create_proof':
            return ProverCreateProofSerializer
        else:
            return super().get_serializer_class()

    @action(methods=['POST'], detail=False)
    def issuer_create_credential_offer(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        serializer = self.get_serializer_class()(data=request.data)
        serializer.is_valid(raise_exception=True)
        params = serializer.create(serializer.validated_data)
        try:
            cred_offer = run_async(
                WalletAgent.issuer_create_credential_offer(
                    agent_name=wallet.uid,
                    pass_phrase=params['pass_phrase'],
                    cred_def_id=params['cred_def_id']
                ),
                timeout=WALLET_AGENT_TIMEOUT
            )
        except WalletOperationError as e:
            raise exceptions.ValidationError(detail=str(e))
        except AgentTimeOutError:
            raise AgentTimeoutError()
        else:
            return Response(data=dict(cred_offer=cred_offer))

    @action(methods=['POST'], detail=False)
    def prover_create_credential_req(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        serializer = self.get_serializer_class()(data=request.data)
        serializer.is_valid(raise_exception=True)
        params = serializer.create(serializer.validated_data)
        try:
            cred_req, cred_req_metadata = run_async(
                WalletAgent.prover_create_credential_req(
                    agent_name=wallet.uid,
                    pass_phrase=params['pass_phrase'],
                    prover_did=params['prover_did'],
                    cred_offer=params['cred_offer'],
                    cred_def=params['cred_def'],
                    master_secret_id=params['link_secret_id']
                ),
                timeout=WALLET_AGENT_TIMEOUT
            )
        except WalletOperationError as e:
            raise exceptions.ValidationError(detail=str(e))
        except AgentTimeOutError:
            raise AgentTimeoutError()
        else:
            return Response(data=dict(
                cred_req=cred_req,
                cred_req_metadata=cred_req_metadata
            ))

    @action(methods=['POST'], detail=False)
    def prover_create_master_secret(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        serializer = self.get_serializer_class()(data=request.data)
        serializer.is_valid(raise_exception=True)
        params = serializer.create(serializer.validated_data)
        try:
            link_secret_id = run_async(
                WalletAgent.prover_create_master_secret(
                    agent_name=wallet.uid,
                    pass_phrase=params['pass_phrase'],
                    master_secret_name=params['link_secret_name']
                ),
                timeout=WALLET_AGENT_TIMEOUT
            )
        except WalletOperationError as e:
            raise exceptions.ValidationError(detail=str(e))
        except AgentTimeOutError:
            raise AgentTimeoutError()
        else:
            return Response(data=dict(link_secret_id=link_secret_id))

    @action(methods=['POST'], detail=False)
    def issuer_create_credential(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        serializer = self.get_serializer_class()(data=request.data)
        serializer.is_valid(raise_exception=True)
        params = serializer.create(serializer.validated_data)
        try:
            encoded_cred_values = dict()
            cred_values = params['cred_values']
            for key, value in cred_values.items():
                encoded_cred_values[key] = dict(raw=str(value), encoded=encode(value))
            cred, cred_revoc_id, revoc_reg_delta = run_async(
                WalletAgent.issuer_create_credential(
                    agent_name=wallet.uid,
                    pass_phrase=params['pass_phrase'],
                    cred_offer=params['cred_offer'],
                    cred_req=params['cred_req'],
                    cred_values=encoded_cred_values,
                    rev_reg_id=params['rev_reg_id']
                ),
                timeout=WALLET_AGENT_TIMEOUT
            )
        except WalletOperationError as e:
            raise exceptions.ValidationError(detail=str(e))
        except AgentTimeOutError:
            raise AgentTimeoutError()
        else:
            return Response(data=dict(
                cred=cred,
                cred_revoc_id=cred_revoc_id,
                revoc_reg_delta=revoc_reg_delta
            ))

    @action(methods=['POST'], detail=False)
    def prover_store_credential(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        serializer = self.get_serializer_class()(data=request.data)
        serializer.is_valid(raise_exception=True)
        params = serializer.create(serializer.validated_data)
        try:
            cred_id = run_async(
                WalletAgent.prover_store_credential(
                    agent_name=wallet.uid,
                    pass_phrase=params['pass_phrase'],
                    cred_req_metadata=params['cred_req_metadata'],
                    cred=params['cred'],
                    cred_def=params['cred_def'],
                    rev_reg_def=params['rev_reg_def'],
                    cred_id=params['cred_id']
                ),
                timeout=WALLET_AGENT_TIMEOUT
            )
        except WalletOperationError as e:
            raise exceptions.ValidationError(detail=str(e))
        except AgentTimeOutError:
            raise AgentTimeoutError()
        else:
            return Response(data=dict(cred_id=cred_id))

    @action(methods=['POST'], detail=False)
    def prover_search_credentials_for_proof_req(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        serializer = ProofRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        params = serializer.create(serializer.validated_data)
        try:
            search_handle = run_async(
                WalletAgent.prover_search_credentials_for_proof_req(
                    agent_name=wallet.uid,
                    pass_phrase=params['pass_phrase'],
                    proof_request=params['proof_req'],
                    extra_query=params['extra_query'],
                    timeout=WALLET_AGENT_TIMEOUT
                ),
                timeout=WALLET_AGENT_TIMEOUT
            )
        except WalletItemNotFound as e:
            raise exceptions.ValidationError(detail=e.error_message)
        except AgentTimeOutError:
            raise AgentTimeoutError()
        else:
            return Response(dict(search_handle=search_handle))

    @action(methods=['POST'], detail=False)
    def prover_close_credentials_search_for_proof_req(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        serializer = CloseSearchHandleSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        params = serializer.create(serializer.validated_data)
        try:
            run_async(
                WalletAgent.prover_close_credentials_search_for_proof_req(
                    agent_name=wallet.uid,
                    pass_phrase=params['pass_phrase'],
                    search_handle=params['search_handle'],
                    timeout=WALLET_AGENT_TIMEOUT
                ),
                timeout=WALLET_AGENT_TIMEOUT
            )
        except WalletItemNotFound as e:
            raise exceptions.ValidationError(detail=e.error_message)
        except AgentTimeOutError:
            raise AgentTimeoutError()
        else:
            return Response()

    @action(methods=['POST'], detail=False)
    def prover_fetch_credentials_for_proof_req(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        serializer = FetchCredForProofRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        params = serializer.create(serializer.validated_data)
        try:
            creds_for_attr = run_async(
                WalletAgent.prover_fetch_credentials_for_proof_req(
                    agent_name=wallet.uid,
                    pass_phrase=params['pass_phrase'],
                    search_handle=params['search_handle'],
                    item_referent=params['item_referent'],
                    count=params['count'],
                    timeout=WALLET_AGENT_TIMEOUT
                ),
                timeout=WALLET_AGENT_TIMEOUT
            )
        except WalletItemNotFound as e:
            raise exceptions.ValidationError(detail=e.error_message)
        except AgentTimeOutError:
            raise AgentTimeoutError()
        else:
            return Response(data=creds_for_attr)

    @action(methods=['POST'], detail=False)
    def prover_create_proof(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        serializer = ProverCreateProofSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        params = serializer.create(serializer.validated_data)
        try:
            try:
                proof = run_async(
                    WalletAgent.prover_create_proof(
                        agent_name=wallet.uid,
                        pass_phrase=params['pass_phrase'],
                        proof_req=params['proof_req'],
                        requested_creds=params['requested_creds'],
                        link_secret_id=params['link_secret_id'],
                        schemas=params['schemas'],
                        cred_defs=params['cred_defs'],
                        rev_states=params['rev_states'],
                        timeout=WALLET_AGENT_TIMEOUT
                    ),
                    timeout=WALLET_AGENT_TIMEOUT
                )
            except Exception as e:
                raise
        except WalletItemNotFound as e:
            raise exceptions.ValidationError(detail=e.error_message)
        except AgentTimeOutError:
            raise AgentTimeoutError()
        else:
            return Response(data=proof)

    def get_wallet(self):
        if 'wallet' in self.get_parents_query_dict():
            wallet_uid = self.get_parents_query_dict()['wallet']
            return get_object_or_404(Wallet.objects, uid=wallet_uid, owner=self.request.user)
        else:
            raise exceptions.NotFound()


class VerifyViewSet(NestedViewSetMixin, viewsets.GenericViewSet):
    """Proving"""
    permission_classes = [IsNonAnonymousUser]
    renderer_classes = [JSONRenderer]
    serializer_class = EmptySerializer

    def get_serializer_class(self):
        if self.action == 'verify':
            return VerifyProofSerializer
        else:
            return super().get_serializer_class()

    @action(methods=['POST'], detail=False)
    def verify_proof(self, request, *args, **kwargs):
        serializer = VerifyProofSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        params = serializer.create(serializer.validated_data)
        try:
            success = run_async(
                verifier_verify_proof(
                    proof_request=params['proof_req'],
                    proof=params['proof'],
                    schemas=params['schemas'],
                    credential_defs=params['cred_defs'],
                    rev_reg_defs=params['rev_reg_defs'],
                    rev_regs=params['rev_regs']
                )
            )
        except Exception as e:
            raise ValidationError(detail=str(e))
        else:
            return Response(data=dict(success=success))
