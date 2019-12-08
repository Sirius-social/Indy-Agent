from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from rest_framework.request import Request


HEADER_PASS_PHRASE = 'WALLET-PASS-PHRASE'


class WalletPassPhraseSerializer(serializers.Serializer):

    pass_phrase = serializers.CharField(max_length=512, required=True)

    def create(self, validated_data):
        return dict(validated_data)

    def update(self, instance, validated_data):
        instance['pass_phrase'] = validated_data.get('pass_phrase')


def try_extract_pass_phrase(request: Request):
    header_name = 'HTTP_' + HEADER_PASS_PHRASE.replace('-', '_')
    try_from_header = request._request.META.get(header_name, None)
    if try_from_header is None:
        serializer = WalletPassPhraseSerializer(data=request.data)
        if serializer.is_valid(raise_exception=False):
            values = serializer.create(serializer.validated_data)
            return values.get('pass_phrase')
        else:
            return None
    else:
        return try_from_header


def extract_pass_phrase(request: Request):
    value = try_extract_pass_phrase(request)
    if value is None:
        raise ValidationError(
            'Expected wallet pass phrase passed via Http header "%s" or '
            'via JSON Post attribute "pass_phrase"' % HEADER_PASS_PHRASE
        )
    return value
