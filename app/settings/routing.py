import importlib

from channels.db import database_sync_to_async as sync_to_async
from channels.routing import ProtocolTypeRouter, URLRouter
from django.conf.urls import url
from django.conf import settings
from django.http.request import HttpRequest

from api.websockets import WalletStatusNotification


application = ProtocolTypeRouter(
    {
        "websocket":
            URLRouter([
                url("^ws/wallets/status/$", WalletStatusNotification),
            ])

    }
)
