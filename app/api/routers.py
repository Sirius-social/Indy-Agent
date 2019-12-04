from rest_framework_extensions.routers import ExtendedDefaultRouter

from .views import *


router = ExtendedDefaultRouter()

# Maintenance subsystem
router.register(r'maintenance', MaintenanceViewSet, base_name='maintenance')
# Wallets administration
wallets_router = router.register(r'agent/admin/wallets', AdminWalletViewSet, base_name='admin-wallets')
# Readonly Ledger
ledger_router_readonly = router.register(r'agent/ledger', LedgerReadOnlyViewSet, base_name='ledger')
# Verifier
verify_router = router.register(r'agent/verify', VerifyViewSet, base_name='verify')

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
# Messaging
messaging_router = wallets_router.register(
    r'messaging',
    MessagingViewSet,
    base_name='wallets-messaging',
    parents_query_lookups=['wallet']
)
# Ledger
ledger_router = did_router.register(
    r'ledger',
    LedgerViewSet,
    base_name='wallets-dids-ledger',
    parents_query_lookups=['wallet', 'self_did']
)
# CredDef
cred_def_router = did_router.register(
    r'cred_def',
    CredDefViewSet,
    base_name='wallets-dids-cred_def',
    parents_query_lookups=['wallet', 'self_did']
)
# Proving
proving_router = wallets_router.register(
    r'proving',
    ProvingViewSet,
    base_name='wallets-proving',
    parents_query_lookups=['wallet']
)
