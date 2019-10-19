from django.db import models

from authentication.models import AgentAccount


class Wallet(models.Model):
    uid = models.CharField(max_length=512, unique=True)
    owner = models.ForeignKey(AgentAccount, on_delete=models.CASCADE, null=True, related_name='wallets')


class SchemaDefinition(models.Model):
    did = models.CharField(max_length=512, db_index=True, null=True)
    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE, null=True)
    schema_id = models.CharField(max_length=512, unique=True, null=True)
    json = models.CharField(max_length=2056, db_index=True)


class CredentialDefinition(models.Model):
    did = models.CharField(max_length=512, db_index=True, null=True)
    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE, null=True)
    cred_def_id = models.CharField(max_length=1024, unique=True)
    cred_def_json = models.TextField()
    cred_def_request = models.TextField(null=True)
    schema = models.CharField(max_length=2056, db_index=True, null=True)
    schema_id = models.CharField(max_length=1024, db_index=True, null=True)
