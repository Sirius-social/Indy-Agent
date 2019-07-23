"""auth URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url, include
from rest_framework.schemas import get_schema_view
from rest_framework.documentation import include_docs_urls

from api.routers import router as api_router


urlpatterns = [
    url(r'^agent', include(api_router.urls)),
]


urlpatterns += [
    url('^schema/agent', get_schema_view(title="Indy Agent Schema", public=True)),
    url(r'^docs/agent', include_docs_urls(title='Indy Agent Docs'))
]
