from django.db import models

from authentication.models import AgentAccount


class Wallet(models.Model):
    uid = models.CharField(max_length=512, unique=True)
    owner = models.ForeignKey(AgentAccount, on_delete=models.CASCADE, null=True, related_name='wallets')
