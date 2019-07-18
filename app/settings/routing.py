from channels.routing import ChannelNameRouter, ProtocolTypeRouter, URLRouter
import asyncio
import json
from datetime import datetime
from django.conf.urls import url
from channels.consumer import AsyncConsumer
from channels.generic.http import AsyncHttpConsumer


class LongPollConsumer(AsyncHttpConsumer):

    async def handle(self, body):
        try:
            await self.send_headers(headers=[
                ("Content-Type".encode("utf-8"), "application/json".encode("utf-8")),
            ])
        except Exception as e:
            raise e
        # Headers are only sent after the first body event.
        # Set "more_body" to tell the interface server to not
        # finish the response yet:
        await self.send_body(b"", more_body=True)

    async def chat_message(self, event):
        # Send JSON and finish the response:
        await self.send_body(json.dumps(event).encode("utf-8"))


class ServerSentEventsConsumer(AsyncHttpConsumer):
    async def handle(self, body):
        try:
            await self.send_headers(headers=[
                ("Cache-Control".encode("utf-8"), "no-cache".encode("utf-8")),
                ("Content-Type".encode("utf-8"), "text/event-stream".encode("utf-8")),
                ("Transfer-Encoding".encode("utf-8"), "chunked".encode("utf-8")),
            ])
        except Exception as e:
            raise e
        while True:
            payload = "data: %s\n\n" % datetime.now().isoformat()
            await self.send_body(payload.encode("utf-8"), more_body=True)
            try:
                await self.channel_layer.send(
                    "printer",
                    {
                        "type": "test.print",
                        "text": payload,
                    },
                )
            except Exception as e:
                print('!!!!!!!' + str(e))
                pass
            await asyncio.sleep(1)


class PrintConsumer(AsyncConsumer):

    async def test_print(self, message):
        print("Test: " + message["text"])
        print(str(self))


application = ProtocolTypeRouter(
    {
        "http": URLRouter([
            url(r"^poll/$", LongPollConsumer),
            url(r"^notifications/(?P<stream>\w+)/$", LongPollConsumer),
            url(r"^events/$", ServerSentEventsConsumer),
        ]),
        "channel": ChannelNameRouter({
            "printer": PrintConsumer,
            "state-machine": None,
        }),
    }
)
