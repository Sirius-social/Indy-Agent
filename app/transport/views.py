import uuid
import json
from urllib.parse import urljoin

from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.generics import get_object_or_404
from rest_framework import exceptions
from rest_framework_extensions.mixins import NestedViewSetMixin
from rest_framework import viewsets
from rest_framework.renderers import JSONRenderer
from rest_framework.decorators import action
from django.http import HttpResponse
from django.urls import reverse
from django.conf import settings

from core.permissions import *
from core.base import ReadOnlyChannel, WriteOnlyChannel, ReadWriteTimeoutError, AsyncReqResp
from core.utils import extract_pass_phrase
from core.wallet import AgentTimeOutError
from core.sync2async import run_async
from core.aries_rfcs.features.feature_0023_did_exchange.feature import DIDExchange as DIDExchangeFeature
from core.aries_rfcs.features.feature_0023_did_exchange.errors import \
    BadInviteException as DIDExchangeBadInviteException
from core.aries_rfcs.features.feature_0160_connection_protocol.feature import ConnectionProtocol
from core.aries_rfcs.features.feature_0160_connection_protocol.errors import BadInviteException
from api.models import Wallet
from .serializers import *
from .const import *
from .utils import *
from .models import Endpoint, Invitation


async def read_from_channel(name: str, timeout: int):
    chan = await ReadOnlyChannel.create(name)
    try:
        log = []
        try:
            while True:
                not_closed, data = await chan.read(timeout)
                if not_closed:
                    message, details = data
                    log.append(
                        dict(
                            message=message,
                            details=details
                        )
                    )
                else:
                    break
            return log
        except ReadWriteTimeoutError:
            raise TimeoutError()
    finally:
        await chan.close()


async def write_to_channel(name: str, data):
    chan = await WriteOnlyChannel.create(name)
    try:
        return await chan.broadcast(data)
    finally:
        await chan.close(silent=True)


class EndpointViewSet(NestedViewSetMixin,
                      viewsets.mixins.RetrieveModelMixin,
                      viewsets.mixins.CreateModelMixin,
                      viewsets.mixins.DestroyModelMixin,
                      viewsets.mixins.ListModelMixin,
                      viewsets.GenericViewSet):
    """Operate with Endpoints"""
    permission_classes = [IsNonAnonymousUser]
    renderer_classes = [JSONRenderer]
    serializer_class = EndpointSerializer
    lookup_field = 'uid'

    def get_queryset(self):
        return Endpoint.objects.filter(owner=self.request.user, wallet=self.get_wallet())

    def get_serializer_class(self):
        if self.action == 'invite':
            return InviteSerializer
        elif self.action == 'create':
            return CreateEndpointSerializer
        else:
            return super().get_serializer_class()

    def perform_create(self, serializer):
        uid = uuid.uuid4().hex
        path = reverse('endpoint', kwargs=dict(uid=uid))
        host = serializer.validated_data.pop('host')
        if host:
            url = urljoin(host, path)
        else:
            host = self.request.META['HTTP_HOST']
            scheme = 'https' if self.request.is_secure() else 'http'
            url = urljoin('%s://%s/' % (scheme, host), path)
        serializer.save(uid=uid, owner=self.request.user, url=url, wallet=self.get_wallet())

    @action(methods=['POST'], detail=True)
    def invite(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        endpoint = self.get_object()
        serializer = InviteSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        entity = serializer.create(serializer.validated_data)
        pass_phrase = extract_pass_phrase(request)
        if entity.get('url', None):
            try:
                for feature in [ConnectionProtocol, DIDExchangeFeature]:
                    log_channel_name = run_async(
                        feature.receive_invite_link(
                            entity['url'],
                            wallet.uid,
                            pass_phrase,
                            request.user.username,
                            endpoint.url,
                            entity['ttl']
                        )
                    )
                    if log_channel_name:
                        try:
                            invite_log = run_async(
                                read_from_channel(log_channel_name, entity['ttl']),
                                timeout=entity['ttl']
                            )
                        except TimeoutError:
                            return Response(
                                data='Invite procedure was terminated by timeout'.encode('utf-8'),
                                status=status.HTTP_408_REQUEST_TIMEOUT
                            )
                        else:
                            return Response(data=invite_log, status=status.HTTP_200_OK)
                raise exceptions.ValidationError('Unknown invitation format')
            except DIDExchangeBadInviteException as e:
                raise exceptions.ValidationError(e.message)
            except BadInviteException as e:
                raise exceptions.ValidationError(e.message)
        elif entity.get('invite_msg', None):
            raise NotImplemented()
        else:
            raise exceptions.ValidationError('You must specify any of fields: "invite_msg" or "invite_link"')

    def get_wallet(self):
        if 'wallet' in self.get_parents_query_dict():
            wallet_uid = self.get_parents_query_dict()['wallet']
            return get_object_or_404(Wallet.objects, uid=wallet_uid, owner=self.request.user)
        else:
            raise exceptions.NotFound()


class InvitationViewSet(NestedViewSetMixin,
                        viewsets.mixins.CreateModelMixin,
                        viewsets.mixins.ListModelMixin,
                        viewsets.GenericViewSet):
    """Manage Invitations"""
    permission_classes = [IsNonAnonymousUser]
    renderer_classes = [JSONRenderer]

    def get_serializer_class(self):
        if self.action == 'create':
            return CreateInvitationSerializer
        else:
            return InvitationSerializer

    def get_queryset(self):
        return Invitation.objects.filter(
            endpoint=self.get_endpoint()
        )

    def list(self, request, *args, **kwargs):
        collection = [
            dict(
                url=x.invitation_url,
                feature=x.feature,
                connection_key=x.connection_key
            )
            for x in self.get_queryset().all()
        ]
        serializer = InvitationSerializer(instance=collection, many=True)
        return Response(data=serializer.data)

    def create(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        serializer = CreateInvitationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        entity = serializer.create(serializer.validated_data)
        pass_phrase = extract_pass_phrase(request)
        invitation_label = entity.get('label') or request.user.username
        # FIRE!!!
        if entity['feature'] == InvitationSerializer.FEATURE_0023_ARIES_RFC:
            invite_string, invite_msg = run_async(
                DIDExchangeFeature.generate_invite_link(
                    label=invitation_label,
                    endpoint=self.get_endpoint().url,
                    agent_name=wallet.uid,
                    pass_phrase=pass_phrase,
                    extra=entity['extra']
                ),
                timeout=10
            )
            connection_key = invite_msg['recipientKeys'][0]
        elif entity['feature'] == InvitationSerializer.FEATURE_0160_ARIES_RFC:
            invite_string, invite_msg = run_async(
                ConnectionProtocol.generate_invite_link(
                    label=invitation_label,
                    endpoint=self.get_endpoint().url,
                    agent_name=wallet.uid,
                    pass_phrase=pass_phrase,
                    extra=entity['extra']
                ),
                timeout=10
            )
            connection_key = invite_msg['recipientKeys'][0]
        else:
            raise exceptions.ValidationError('Unexpected feature: %s' % entity['feature'])
        instance = Invitation.objects.create(
            endpoint=self.get_endpoint(),
            invitation_string=invite_string,
            feature=entity['feature'],
            connection_key=connection_key
        )
        entity['url'] = instance.invitation_url
        entity['connection_key'] = connection_key
        serializer = CreateInvitationSerializer(instance=entity)
        return Response(data=serializer.data, status=status.HTTP_201_CREATED)

    def get_endpoint(self):
        if 'endpoint' in self.get_parents_query_dict():
            endpoint_uid = self.get_parents_query_dict()['endpoint']
            wallet = self.get_wallet()
            return get_object_or_404(Endpoint.objects, uid=endpoint_uid, wallet=wallet)
        else:
            raise exceptions.NotFound()

    def get_wallet(self):
        if 'wallet' in self.get_parents_query_dict():
            wallet_uid = self.get_parents_query_dict()['wallet']
            return get_object_or_404(Wallet.objects, uid=wallet_uid, owner=self.request.user)
        else:
            raise exceptions.NotFound()


@api_view(http_method_names=['POST'])
def endpoint(request, uid):
    instance = Endpoint.objects.filter(uid=uid).first()
    response_timeout = settings.INDY['WALLET_SETTINGS']['TIMEOUTS']['AGENT_REQUEST']
    if instance:
        if request.content_type not in WIRED_CONTENT_TYPES + JSON_CONTENT_TYPES:
            return Response(status=status.HTTP_406_NOT_ACCEPTABLE)
        processed = False
        if request.content_type in WIRED_CONTENT_TYPES:
            try:
                for feature in [ConnectionProtocol, DIDExchangeFeature]:
                    success = run_async(
                        feature.handle(
                            agent_name=instance.wallet.uid,
                            wire_message=request.body,
                            my_label=instance.owner.username,
                            my_endpoint=instance.url
                        ),
                        timeout=response_timeout
                    )
                    processed = processed or success
            except AgentTimeOutError:
                return Response(status=status.HTTP_410_GONE)
            if processed:
                return Response(status=status.HTTP_202_ACCEPTED)
        if not processed:
            count = run_async(
                write_to_channel(
                    name=make_wallet_wired_messages_channel_name(instance.wallet.uid),
                    data=dict(
                        content_type=request.content_type,
                        transport=json.loads(request.body.decode('utf-8'))
                    )
                )
            )
            if count > 0:
                return Response(status=status.HTTP_202_ACCEPTED)
            else:
                return Response(status=status.HTTP_410_GONE)
    else:
        return HttpResponse(status=status.HTTP_404_NOT_FOUND)
