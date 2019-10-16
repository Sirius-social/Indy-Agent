import asyncio

from django.core.management.base import BaseCommand
from django.conf import settings

from authentication.models import AgentAccount


class Command(BaseCommand):

    help = 'Initialize application'

    def handle(self, *args, **options):
        if settings.ROOT_USERNAME and settings.ROOT_PASSWORD:
            root_account, created = AgentAccount.objects.get_or_create(
                defaults=dict(is_staff=True, is_active=True, is_superuser=True),
                username=settings.ROOT_USERNAME
            )
            root_account.set_password(settings.ROOT_PASSWORD)
            root_account.save()
