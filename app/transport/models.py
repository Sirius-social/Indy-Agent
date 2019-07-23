import uuid

from django.db import models
from django.dispatch import receiver


from authentication.models import AgentAccount


class Endpoint(models.Model):
    uid = models.CharField(max_length=2083, primary_key=True)
    owner = models.ForeignKey(AgentAccount, related_name='endpoints', on_delete=models.CASCADE)


@receiver(models.signals.post_delete, sender=AgentAccount)
def create_default_endpoint(sender, instance, **kwargs):
    Endpoint.objects.create(uid=uuid.uuid4().hex, owner=instance)

