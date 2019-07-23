from django.db import models

from authentication.models import AgentAccount




class Wallet(models.Model):

    STATUSES = (
        ('opened', 'Opened'),
        ('closed', 'Closed'),
    )

    owner = models.ForeignKey(AgentAccount, on_delete=models.CASCADE, related_name='wallets')
    name = models.CharField(max_length=512)
    status = models.CharField(max_length=64, choices=STATUSES, null=True)
