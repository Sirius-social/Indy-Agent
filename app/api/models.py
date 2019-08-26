from django.db import models
from django.dispatch import receiver

from authentication.models import AgentAccount


class Wallet(models.Model):
    uid = models.CharField(max_length=512, unique=True)
    owner = models.ForeignKey(AgentAccount, on_delete=models.CASCADE, null=True)


class Connection(models.Model):
    value = models.CharField(max_length=128)
    owner = models.ForeignKey(AgentAccount, on_delete=models.CASCADE)
    wallet = models.ForeignKey(Wallet, on_delete=models.SET_NULL, null=True)
