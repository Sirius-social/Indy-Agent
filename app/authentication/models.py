from django.db import models
from django.contrib.auth.models import AbstractUser


class AgentAccount(AbstractUser):

    agent_name = models.CharField(max_length=64, unique=True, null=True)

    class Meta(AbstractUser.Meta):
        swappable = 'AUTH_USER_MODEL'
