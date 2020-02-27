import base64

from django.utils.translation import ugettext_lazy as _
from rest_framework.exceptions import ValidationError


def validate_nym_request_role(value: str):
    # null (common USER)
    # empty string to reset role
    if value not in [None, 'TRUSTEE', 'STEWARD', 'TRUST_ANCHOR', 'NETWORK_MONITOR', '']:
        raise ValidationError(detail=_('Invalid value.'))


def is_base64(s: str):
    try:
        return base64.b64encode(base64.b64decode(s)) == s.encode()
    except Exception:
        return False
