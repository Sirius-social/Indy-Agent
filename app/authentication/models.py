from django.db import models
from django.contrib.auth.models import AbstractUser


class AgentAccount(AbstractUser):

    class Meta(AbstractUser.Meta):
        swappable = 'AUTH_USER_MODEL'
