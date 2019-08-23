from django.db import models
from django.contrib.postgres.fields import JSONField

from authentication.models import AgentAccount
from api.models import Wallet


class Endpoint(models.Model):
    uid = models.CharField(max_length=2083, primary_key=True)
    owner = models.ForeignKey(AgentAccount, related_name='endpoints', on_delete=models.CASCADE)
    wallet = models.ForeignKey(Wallet, related_name='endpoints', on_delete=models.CASCADE, null=True)
    url = models.URLField(null=True)


class Invitation(models.Model):
    endpoint = models.ForeignKey(Endpoint, on_delete=models.CASCADE, related_name='invitations')
    invitation_string = models.CharField(max_length=1024)
    invite_message = JSONField()
