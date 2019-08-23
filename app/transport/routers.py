from api.routers import wallets_router

from .views import *


# /agent/admin/wallets/<uid>/endpoints/
wallets_router.register(
    r'endpoints',
    EndpointViewSet,
    base_name='wallets-endpoint',
    parents_query_lookups=['wallet']
)
