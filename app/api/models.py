from django.db import models

from authentication.models import AgentAccount
from transport.models import Endpoint


class Wallet(models.Model):
    uid = models.CharField(max_length=512, unique=True)
    endpoint = models.OneToOneField(Endpoint, on_delete=models.SET_NULL, null=True)
    owner = models.ForeignKey(AgentAccount, on_delete=models.SET_NULL, null=True)
