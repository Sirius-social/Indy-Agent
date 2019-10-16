from django.utils.translation import ugettext_lazy as _
from rest_framework import status
from rest_framework.exceptions import APIException


class ConflictError(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = _('Content conflict.')
    default_code = 'content_conflict'


class AgentTimeoutError(APIException):
    status_code = status.HTTP_408_REQUEST_TIMEOUT
    default_detail = _('Agent timeout')
    default_code = 'agent_timeout'
