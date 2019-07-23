from django.db import models
from django.contrib.postgres.fields import JSONField
from django.dispatch import receiver

from transport.models import Endpoint


class StateMachine(models.Model):
    id = models.CharField(max_length=512, primary_key=True)
    last_access = models.DateTimeField(auto_now=True)
    context = JSONField()
    endpoint_uid = models.CharField(max_length=2083, db_index=True, null=True)


@receiver(models.signals.post_delete, sender=Endpoint)
def auto_clean_state_machines(sender, instance, **kwargs):
    StateMachine.objects.filter(endpoint_uid=instance.uid).all().delete()
    pass
