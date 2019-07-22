import hashlib

from django.db import models


class TransportDescriptor(models.Model):

    entrypoint = models.CharField(max_length=2083, db_index=True)
    nonce = models.CharField(max_length=128, db_index=True)
    last_access = models.DateTimeField(null=True, db_index=True)

    @property
    def channel_name(self):
        compound = ':'.join([self.entrypoint, self.nonce])
        h = hashlib.sha1(compound)
        return h.hexdigest()

    class Meta:
        unique_together = ('entrypoint', 'nonce')

