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
from core.aries_rfcs.features.feature_0023_did_exchange.feature import DIDExchange as DIDExchangeFeature
from core.aries_rfcs.features.feature_0023_did_exchange.errors import \
    BadInviteException as DIDExchangeBadInviteException
from core.non_standard.features.connections.connection import Connection as NonStandardDIDExchangeFeature
from core.non_standard.features.connections.errors import BadInviteException as NonStandardDIDExchangeBadInviteException
from api.models import Wallet
from .serializers import *
from .models import Endpoint


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
    queryset = Endpoint.objects.all()

    def get_queryset(self):
        return Endpoint.objects.filter(owner=self.request.user, wallet=self.get_wallet())

    def perform_create(self, serializer):
        host = self.request.META['HTTP_HOST']
        scheme = 'https' if self.request.is_secure() else 'http'
        url = urljoin('%s://%s/' % (scheme, host), serializer.validated_data['uid'])
        serializer.save(owner=self.request.user, url=url, wallet=self.get_wallet())

    def get_wallet(self):
        if 'wallet' in self.get_parents_query_dict():
            wallet_uid = self.get_parents_query_dict()['wallet']
            return get_object_or_404(Wallet.objects, uid=wallet_uid)
        else:
            raise exceptions.NotFound()
