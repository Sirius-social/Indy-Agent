from django.db import models
from django.contrib.auth.models import AbstractUser


class AgentAccount(AbstractUser):

    agent_name = models.CharField(max_length=64, unique=True, null=True)
    pass_phrase = models.CharField(max_length=128, null=True)

    class Meta(AbstractUser.Meta):
        swappable = 'AUTH_USER_MODEL'
