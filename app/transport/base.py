import hashlib

from .models import TransportDescriptor


class Transporter(object):

    def __init__(self, content_type, body):
        self.content_type = content_type
        self.body = body


class InboundTransportBase(object):

    def __init__(self, entrypoint: str):
        self.entrypoint = entrypoint
        h = hashlib.sha1(entrypoint.encode())
        self.descriptor = TransportDescriptor.objects.get_or_create(
            entrypoint=entrypoint, defaults=dict(channel_name=h.hexdigest())
        )


class OutboundTransportBase(object):
    pass
