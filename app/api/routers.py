from rest_framework_extensions.routers import ExtendedDefaultRouter

from .views import *


router = ExtendedDefaultRouter()

# Maintenance subsystem
router.register(r'maintenance', MaintenanceViewSet, base_name='maintenance')
# Wallets administration
wallets_router = router.register(r'agent/admin/wallets', AdminWalletViewSet, base_name='admin-wallets')
# Wallet pairwise discovery
pairwise_router = wallets_router.register(
    r'pairwise',
    PairwiseViewSet,
    base_name='wallets-pairwise',
    parents_query_lookups=['wallet']
)
# DID manage
did_router = wallets_router.register(
    r'did',
    DIDViewSet,
    base_name='wallets-did',
    parents_query_lookups=['wallet']
)
# Ledger
ledger_router = did_router.register(
    r'ledger',
    LedgerViewSet,
    base_name='wallets-dids-ledger',
    parents_query_lookups=['wallet', 'self_did']
)
