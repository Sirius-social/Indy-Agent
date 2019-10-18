"""
Django settings for auth project.

Generated by 'django-admin startproject' using Django 1.11.4.

For more information on this file, see
https://docs.djangoproject.com/en/1.11/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.11/ref/settings/
"""

import os
import socket
from ctypes import *

from django.core.management.utils import get_random_secret_key

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.11/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv('SECRET_KEY', None) or get_random_secret_key()
assert SECRET_KEY, 'SECRET_KEY environ variable must be set'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'channels',
    'rest_framework',
    'core',
    'api',
    'authentication',
    'transport',
    'state_machines'
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

AUTH_USER_MODEL = 'authentication.AgentAccount'
ROOT_URLCONF = 'settings.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            os.path.join(BASE_DIR, 'templates')
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

# Database
# https://docs.djangoproject.com/en/1.11/ref/settings/#databases
DATABASE_CONN_MAX_AGE = int(os.getenv('DATABASE_CONN_MAX_AGE', 0))
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('DATABASE_NAME') or 'postgres',
        'USER': os.environ.get('DATABASE_USER') or 'postgres',
        'PASSWORD': os.environ.get('DATABASE_PASSWORD') or 'postgres',
        'HOST': os.environ.get('DATABASE_HOST') or 'db',
        'PORT': os.environ.get('DATABASE_PORT') or 5432,
        'CONN_MAX_AGE': DATABASE_CONN_MAX_AGE
    }
}
DATABASES['primary'] = DATABASES['default']

WSGI_APPLICATION = 'settings.wsgi.application'
ASGI_APPLICATION = 'settings.routing.application'

# Internationalization
# https://docs.djangoproject.com/en/1.11/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.11/howto/static-files/

STATIC_URL = '/static/agent/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'


REST_FRAMEWORK = {
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.LimitOffsetPagination',
    'PAGE_SIZE': 100,
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework.authentication.BasicAuthentication',
    ),
    'DEFAULT_RENDERER_CLASSES': (
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
    )
}


VERSION = {
    'MAJOR': int(os.getenv('VERSION').split('.')[0]),
    'MINOR': int(os.getenv('VERSION').split('.')[1])
}


# MemCached custer settings
MEMCACHE_CLUSTER = None
if os.getenv('MEMCACHE.HOSTBYNAME'):
    # Kubernetes compatibility: see https://cloud.google.com/solutions/deploying-memcached-on-kubernetes-engine
    _, _, ips = socket.gethostbyname_ex(os.getenv('MEMCACHE.HOSTBYNAME'))
    MEMCACHE_CLUSTER = [(ip, 11211) for ip in ips]
else:
    ip = os.getenv('MEMCACHE.IP') or 'cache'
    MEMCACHE_CLUSTER = [(ip, 11211)]


CACHES_LOCATION = ["%s:%d" % (ip, port) for ip, port in MEMCACHE_CLUSTER]


CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.memcached.MemcachedCache',
        'LOCATION': CACHES_LOCATION,
        'KEY_PREFIX': 'agent_default',
        'VERSION': 1
    },
    'state_machines': {
        'BACKEND': 'django.core.cache.backends.memcached.MemcachedCache',
        'LOCATION': CACHES_LOCATION,
        'KEY_PREFIX': 'agent_state_machines',
        'VERSION': 1
    }
}


REDIS_ADDRESS = os.getenv('REDIS', 'redis')
REDIS_CONN_TIMEOUT = 5.0

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [(REDIS_ADDRESS, 6379)],
        },
    },
}

WORKERS = int(os.getenv('WORKERS', 4))

INDY = {
    'WALLET_SETTINGS': {
        'storage_driver': '/usr/lib/libindystrgpostgres.so',
        'storage_entrypoint': 'postgresstorage_init',
        'config': {
            'storage_type': 'postgres_storage',
            'storage_config': {"url": "{}:{}".format(DATABASES['primary']['HOST'], DATABASES['primary']['PORT'])}
        },
        'credentials': {
            'storage_credentials': {
                "account": DATABASES['primary']['USER'],
                "password": DATABASES['primary']['PASSWORD'],
                "admin_account": DATABASES['primary']['USER'],
                "admin_password": DATABASES['primary']['PASSWORD']
            }
        },
        'TIMEOUTS': {
            'CREATE_DELETE': 30,  # sec
            'AGENT_REQUEST': 5,  # timeout SEC
            'AGENT_START': 5,  # timeout SEC
            'CRED_DEF_STORE': 30
        }
    },
    'INVITATION_URL_BASE': os.getenv('INDY_INVITATION_URL_BASE', 'https://socialsirius.com/invitation'),
    'GENESIS_TXN_FILE_PATH': os.getenv('INDY_GENESIS_TXN_FILE_PATH', '/home/indy/sandbox/pool_transactions_genesis'),
    'PROTOCOL_VERSION': 2,
    'POOL_NAME': os.getenv('INDY_POOL_NAME', 'pool')
}
stg_lib = CDLL(INDY['WALLET_SETTINGS']['storage_driver'])
touch_lib = stg_lib[INDY['WALLET_SETTINGS']['storage_entrypoint']]()
assert touch_lib == 0, 'Error while loading Indy storage driver'


SENTRY_DSN = "https://ad4cf1da201c40849413ecc7ecc1422a@sentry.io/1550449"

ROOT_USERNAME = os.getenv('ROOT_USERNAME')
ROOT_PASSWORD = os.getenv('ROOT_PASSWORD')
