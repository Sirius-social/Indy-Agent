import hashlib

from django.db import models

from authentication.models import AgentAccount


class EntrypointDescriptor(models.Model):

    id = models.CharField(max_length=2083, primary_key=True)
    owner = models.ForeignKey(AgentAccount, related_name='entrypoints', on_delete=models.CASCADE)


class TransportDescriptor(models.Model):

    entrypoint = models.ForeignKey(EntrypointDescriptor, related_name='nonces', on_delete=models.CASCADE)
    nonce = models.CharField(max_length=128, db_index=True)
    last_access = models.DateTimeField(null=True, db_index=True)

    @property
    def channel_name(self):
        compound = ':'.join([self.entrypoint, self.nonce])
        h = hashlib.sha1(compound)
        return h.hexdigest()

    class Meta:
        unique_together = ('entrypoint', 'nonce')

