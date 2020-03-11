import json
import uuid
import platform


class ProvisionConfig:

    DEFAULT_WALLET_KEY = 'key'

    def __init__(self, agency_did, agency_verkey, **kwargs):
        self.agency_url = kwargs.get('agency_url', 'http://localhost:8080')
        self.agency_did = agency_did
        self.agency_verkey = agency_verkey
        unique_wallet_name = 'wallet_' + uuid.uuid4().hex
        self.wallet_name = kwargs.get('wallet_name', unique_wallet_name)
        self.wallet_key = kwargs.get('wallet_key', self.DEFAULT_WALLET_KEY)
        self.payment_method = 'null',
        self.enterprise_seed = kwargs.get('enterprise_seed', '000000000000000000000000Trustee1')
        self.protocol_type = '2.0'
        self.communication_method = 'aries'

    def to_json(self):
        return {
            'agency_url': self.agency_url,
            'agency_did': self.agency_did,
            'agency_verkey': self.agency_verkey,
            'wallet_name': self.wallet_name,
            'wallet_key': self.wallet_key,
            'payment_method': self.payment_method,
            'enterprise_seed': self.enterprise_seed,
            'protocol_type': self.protocol_type,
            'communication_method': self.communication_method
        }

    def __str__(self):
        return json.dumps(self.to_json(), indent=2, sort_keys=True)


class Invitation:

    def __init__(self, label: str, recipient_keys: list, service_endpoint: str, routing_keys: list):
        self.label = label
        self.recipientKeys = recipient_keys
        self.serviceEndpoint = service_endpoint
        self.routingKeys = routing_keys

    def to_json(self):
        return {
            "@id": uuid.uuid4().hex,
            "@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/invitation",
            "label": self.label,
            "recipientKeys": self.recipientKeys,
            "serviceEndpoint": self.serviceEndpoint,
            "routingKeys": self.routingKeys
        }

    def __str__(self):
        return json.dumps(self.to_json(), indent=2, sort_keys=True)


EXTENSION = {"darwin": ".dylib", "linux": ".so", "win32": ".dll", 'windows': '.dll'}


def file_ext():
    your_platform = platform.system().lower()
    return EXTENSION[your_platform] if (your_platform in EXTENSION) else '.so'
