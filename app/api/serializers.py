from rest_framework import serializers
from rest_framework.exceptions import ValidationError


class EmptySerializer(serializers.Serializer):

    def create(self, validated_data):
        return dict(validated_data)

    def update(self, instance, validated_data):
        pass


class WalletAccessSerializer(serializers.Serializer):

    pass_phrase = serializers.CharField(max_length=512, required=True)

    def create(self, validated_data):
        return dict(validated_data)

    def update(self, instance, validated_data):
        instance['pass_phrase'] = validated_data.get('pass_phrase')


class WalletCreateSerializer(WalletAccessSerializer):

    uid = serializers.CharField(max_length=512, required=True)
    endpoint = serializers.CharField(max_length=2083, allow_null=True, required=False)

    def update(self, instance, validated_data):
        super().update(instance, validated_data)
        instance['uid'] = validated_data.get('uid')
        instance['endpoint'] = validated_data.get('endpoint')


class WalletRetrieveSerializer(serializers.Serializer):

    uid = serializers.CharField(max_length=512, required=True)
    endpoint = serializers.CharField(max_length=2083, allow_null=True)

    def create(self, validated_data):
        return dict(validated_data)

    def update(self, instance, validated_data):
        instance['uid'] = validated_data.get('uid')
        instance['endpoint'] = validated_data.get('endpoint')


def validate_feature(value):
    expected = [GenerateInviteLinkSerializer.FEATURE_0023_ARIES_RFC, GenerateInviteLinkSerializer.FEATURE_CUSTOM_CONN]
    if value not in expected:
        raise ValidationError('Expected values: [%s]' % ','.join(expected))


class GenerateInviteLinkSerializer(WalletAccessSerializer):

    FEATURE_0023_ARIES_RFC = 'aries_rfcs_0023'
    FEATURE_CUSTOM_CONN = 'connection'

    feature = serializers.CharField(max_length=36, default=FEATURE_0023_ARIES_RFC, validators=[validate_feature])
    invite_link = serializers.CharField(max_length=2083, required=False)
    invite_msg = serializers.JSONField(required=False)

    def update(self, instance, validated_data):
        instance['feature'] = validated_data.get('feature')
        instance['invite_link'] = validated_data.get('invite_link', None)
        instance['invite_msg'] = validated_data.get('invite_msg', None)
