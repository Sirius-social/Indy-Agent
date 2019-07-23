from channels.generic.http import AsyncHttpConsumer
from rest_framework import status

from .models import Endpoint


class HttpEndpoint(AsyncHttpConsumer):

    async def handle(self, body):
        await self.send_headers(headers=[
            ("Content-Type".encode("utf-8"), "application/json".encode("utf-8")),
        ])
        transport = Endpoint.objects.filter(uid=self.scope["url_route"]["kwargs"]["uid"]).first()
        if transport:
            await self.send_body(b"", more_body=True)
        else:
            await self.send_response(status=status.HTTP_404_NOT_FOUND, body=b"")
