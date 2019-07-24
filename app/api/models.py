from django.db import models
from django.dispatch import receiver

from authentication.models import AgentAccount
from transport.models import Endpoint


class Wallet(models.Model):
    uid = models.CharField(max_length=512, unique=True)
    endpoint = models.OneToOneField(Endpoint, on_delete=models.SET_NULL, null=True)
    owner = models.ForeignKey(AgentAccount, on_delete=models.SET_NULL, null=True)


@receiver(models.signals.post_delete, sender=Wallet)
def create_default_endpoint(sender, instance, **kwargs):
    if instance.endpoint:
        instance.endpoint.delete()
