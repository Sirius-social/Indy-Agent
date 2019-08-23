from api.routers import wallets_router

from .views import *


# /agent/admin/wallets/<uid>/endpoints/
endpoints_router = wallets_router.register(
    r'endpoints',
    EndpointViewSet,
    base_name='wallets-endpoint',
    parents_query_lookups=['wallet']
)
# /agent/admin/wallets/<uid>/endpoints/<uid>/invitations/
invitations_router = endpoints_router.register(
    r'invitations',
    InvitationViewSet,
    base_name='endpoints-invitation',
    parents_query_lookups=['wallet', 'endpoint']
)
