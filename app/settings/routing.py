from channels.routing import ChannelNameRouter, ProtocolTypeRouter, URLRouter
from django.conf.urls import url
from channels.auth import AuthMiddlewareStack

from transport.endpoints import HttpEndpoint
from api.views import OpenWalletApiView


application = ProtocolTypeRouter(
    {
        # "http": URLRouter([
        #     url(r"^agent/endpoints/(?P<uid>\w+)/$", HttpEndpoint),
        # ]),
        # "http": AuthMiddlewareStack(
        #     URLRouter([
        #         url(r"agent/admin/wallets/open/$", OpenWalletApiView),
        #     ])
        # )
    }
)
