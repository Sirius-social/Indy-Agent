from channels.generic.http import AsyncHttpConsumer


class HttpEndpoint(AsyncHttpConsumer):

    async def handle(self, body):
        await self.send_headers(headers=[
            ("Content-Type".encode("utf-8"), "application/json".encode("utf-8")),
        ])
        endpoint_id = self.scope["url_route"]["kwargs"]["id"]
        await self.send_body(b"", more_body=True)
