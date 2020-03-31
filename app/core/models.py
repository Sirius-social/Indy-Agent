import json
from django.db import models
from channels.db import database_sync_to_async


class StartedStateMachine(models.Model):
    machine_id = models.CharField(max_length=512, primary_key=True)
    machine_class_name = models.CharField(max_length=512)


class CredDef(models.Model):
    cred_def_id = models.CharField(max_length=128, unique=True)
    body = models.TextField()


class IssuerSchema(models.Model):
    schema_id = models.CharField(max_length=128, unique=True)
    body = models.TextField()


async def update_cred_def_meta(cred_def_id: str, body: dict):
    await database_sync_to_async(__update_cred_def_meta)(cred_def_id, body)


async def get_cred_def_meta(cred_def_id: str):
    return await database_sync_to_async(__get_cred_def_meta)(cred_def_id)


def __update_cred_def_meta(cred_def_id: str, body: dict):
    body_str = json.dumps(body)
    CredDef.objects.get_or_create(
        cred_def_id=cred_def_id, defaults=dict(body=body_str)
    )


def __get_cred_def_meta(cred_def_id: str):
    return CredDef.objects.filter(cred_def_id=cred_def_id).first()
