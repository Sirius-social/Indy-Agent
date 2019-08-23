from rest_framework_extensions.routers import ExtendedDefaultRouter

from .views import *


router = ExtendedDefaultRouter()

# Maintenance subsystem
wallets_router = router.register(r'agent/admin/wallets', AdminWalletViewSet, base_name='admin-wallets')
