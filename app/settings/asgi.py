import os
import django
from channels.routing import get_default_application
from sentry_asgi import SentryMiddleware

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings.production")
django.setup()
application = get_default_application()
application = SentryMiddleware(application)
