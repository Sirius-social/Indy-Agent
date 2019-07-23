from django.db import models
from django.contrib.postgres.fields import JSONField

from transport.models import Endpoint


class StateMachine(models.Model):
    id = models.CharField(max_length=512, primary_key=True)
    last_access = models.DateTimeField(auto_now=True)
    context = JSONField()
