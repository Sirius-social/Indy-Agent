import os

import sentry_sdk
from sentry_sdk.integrations.django import DjangoIntegration

from .base import *


DEBUG = False
ALLOWED_HOSTS = ['*']


sentry_sdk.init(
    dsn=SENTRY_DSN,
    integrations=[DjangoIntegration()]
)


SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
