import uuid
from urllib.parse import urljoin

from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import get_object_or_404
from rest_framework import exceptions
from rest_framework_extensions.mixins import NestedViewSetMixin
from rest_framework import viewsets
from rest_framework.renderers import JSONRenderer
from rest_framework.decorators import action
from django.db import transaction, connection

from core.permissions import *
from core.sync2async import run_async
from core.non_standard.features.connections.connection import Connection as ConnectionFeature
from core.aries_rfcs.features.feature_0023_did_exchange.feature import DIDExchange as DIDExchangeFeature
from core.aries_rfcs.features.feature_0023_did_exchange.errors import \
    BadInviteException as DIDExchangeBadInviteException
from core.non_standard.features.connections.connection import Connection as NonStandardDIDExchangeFeature
from core.non_standard.features.connections.errors import BadInviteException as NonStandardDIDExchangeBadInviteException
from api.models import Wallet
from .serializers import *
from .models import Endpoint, Invitation


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

    def perform_create(self, serializer):
        host = self.request.META['HTTP_HOST']
        scheme = 'https' if self.request.is_secure() else 'http'
        uid = uuid.uuid4().hex
        url = urljoin('%s://%s/' % (scheme, host), uid)
        serializer.save(uid=uid, owner=self.request.user, url=url, wallet=self.get_wallet())

    def get_wallet(self):
        if 'wallet' in self.get_parents_query_dict():
            wallet_uid = self.get_parents_query_dict()['wallet']
            return get_object_or_404(Wallet.objects, uid=wallet_uid)
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
        collection = [dict(url=x.invitation_url, feature=x.feature) for x in self.get_queryset().all()]
        serializer = InvitationSerializer(instance=collection, many=True)
        return Response(data=serializer.data)

    def create(self, request, *args, **kwargs):
        wallet = self.get_wallet()
        serializer = CreateInvitationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        entity = serializer.create(serializer.validated_data)
        # FIRE!!!
        if entity['feature'] == InvitationSerializer.FEATURE_0023_ARIES_RFC:
            invite_string, invite_msg = run_async(
                DIDExchangeFeature.generate_invite_link(
                    label=request.user.username,
                    endpoint=self.get_endpoint().url,
                    agent_name=wallet.uid,
                    pass_phrase=entity['pass_phrase']
                )
            )
        elif entity['feature'] == InvitationSerializer.FEATURE_CUSTOM_CONN:
            invite_string, invite_msg = run_async(
                ConnectionFeature.generate_invite_link(
                    label=request.user.username,
                    endpoint=self.get_endpoint().url,
                    agent_name=wallet.uid,
                    pass_phrase=entity['pass_phrase']
                )
            )
        else:
            raise exceptions.ValidationError('Unexpected feature: %s' % entity['feature'])
        instance = Invitation.objects.create(
            endpoint=self.get_endpoint(),
            invitation_string=invite_string,
            feature=entity['feature']
        )
        entity['url'] = instance.invitation_url
        serializer = CreateInvitationSerializer(instance=entity)
        return Response(data=serializer.data, status=status.HTTP_201_CREATED)

    def get_endpoint(self):
        if 'endpoint' in self.get_parents_query_dict():
            endpoint_uid = self.get_parents_query_dict()['endpoint']
            return get_object_or_404(Endpoint.objects, uid=endpoint_uid)
        else:
            raise exceptions.NotFound()

    def get_wallet(self):
        if 'wallet' in self.get_parents_query_dict():
            wallet_uid = self.get_parents_query_dict()['wallet']
            return get_object_or_404(Wallet.objects, uid=wallet_uid)
        else:
            raise exceptions.NotFound()
