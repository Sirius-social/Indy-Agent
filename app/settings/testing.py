import sentry_sdk
from sentry_sdk.integrations.django import DjangoIntegration
from .base import *

ALLOWED_HOSTS = ['*']
DEBUG = True
TEST_RUNNER = "teamcity.django.TeamcityDjangoRunner"

SENTRY_ENABLE = False
