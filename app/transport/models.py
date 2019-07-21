from django.db import models


class TransportDescriptor(models.Model):

    entrypoint = models.CharField(max_length=2083, db_index=True)
    channel_name = models.CharField(max_length=128, db_index=True)
