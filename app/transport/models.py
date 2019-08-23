from django.db import models


from authentication.models import AgentAccount
from api.models import Wallet


class Endpoint(models.Model):
    uid = models.CharField(max_length=2083, primary_key=True)
    owner = models.ForeignKey(AgentAccount, related_name='endpoints', on_delete=models.CASCADE)
    wallet = models.ForeignKey(Wallet, related_name='endpoints', on_delete=models.CASCADE, null=True)
    url = models.URLField(null=True)
