from django.db import models

from authentication.models import AgentAccount


class Wallet(models.Model):
    owner = models.ForeignKey(AgentAccount, on_delete=models.CASCADE, related_name='wallets')
    name = models.CharField(max_length=512)

