from rest_framework_extensions.routers import ExtendedDefaultRouter

from .views import *


router = ExtendedDefaultRouter()

# Maintenance subsystem
router.register(r'admin/wallets', AdminWalletViewSet, base_name='admin-wallets')
