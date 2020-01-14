from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from .models import Endpoint


class EndpointSerializer(serializers.ModelSerializer):

    uid = serializers.CharField(max_length=128, read_only=True)

    class Meta:
        model = Endpoint
        fields = ('uid', 'url')
        read_only_fields = ('uid', 'url')


class CreateEndpointSerializer(EndpointSerializer):

    host = serializers.URLField(required=False, allow_null=True, default=None)

    class Meta(EndpointSerializer.Meta):
        fields = list(EndpointSerializer.Meta.fields) + ['host']


def validate_feature(value):
    expected = [InvitationSerializer.FEATURE_0023_ARIES_RFC, InvitationSerializer.FEATURE_0160_ARIES_RFC]
    if value not in expected:
        raise ValidationError('Expected values: [%s]' % ','.join(expected))


class InvitationSerializer(serializers.Serializer):

    FEATURE_0023_ARIES_RFC = 'feature_0023'
    FEATURE_0160_ARIES_RFC = 'feature_0160'

    url = serializers.CharField(max_length=2083, required=False)
    feature = serializers.CharField(
        max_length=36,
        default=FEATURE_0160_ARIES_RFC,
        validators=[validate_feature],
        help_text='Available values: [%s]' % ','.join([FEATURE_0023_ARIES_RFC, FEATURE_0160_ARIES_RFC])
    )
    connection_key = serializers.CharField(max_length=128, required=False)

    def create(self, validated_data):
        return dict(validated_data)

    def update(self, instance, validated_data):
        instance['url'] = validated_data.get('url', None)
        instance['feature'] = validated_data.get('feature')
        instance['connection_key'] = validated_data.get('connection_key', None)


class CreateInvitationSerializer(InvitationSerializer):

    pass_phrase = serializers.CharField(max_length=512, required=True)
    label = serializers.CharField(max_length=128, required=False, allow_null=True, default=None)
    extra = serializers.JSONField(required=False, default={})

    def update(self, instance, validated_data):
        instance['pass_phrase'] = validated_data.get('pass_phrase')
        instance['label'] = validated_data.get('label', None)


class InviteSerializer(serializers.Serializer):

    pass_phrase = serializers.CharField(max_length=512, required=True)
    url = serializers.CharField(max_length=2083, required=True)
    ttl = serializers.IntegerField(
        min_value=5, max_value=60, required=False, default=10, help_text='Connection timeout (sec)'
    )

    def create(self, validated_data):
        return dict(validated_data)

    def update(self, instance, validated_data):
        instance['url'] = validated_data.get('url', None)
        instance['pass_phrase'] = validated_data.get('pass_phrase', None)
        instance['ttl'] = validated_data.get('ttl')
