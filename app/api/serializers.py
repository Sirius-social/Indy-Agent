from rest_framework import serializers

from .validators import *


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

    def update(self, instance, validated_data):
        super().update(instance, validated_data)
        instance['uid'] = validated_data.get('uid')


class WalletRetrieveSerializer(serializers.Serializer):

    uid = serializers.CharField(max_length=512, required=True)

    def create(self, validated_data):
        return dict(validated_data)

    def update(self, instance, validated_data):
        instance['uid'] = validated_data.get('uid')


class DIDAccessSerializer(WalletAccessSerializer):

    their_did = serializers.CharField(max_length=1024, required=True)

    def update(self, instance, validated_data):
        super().update(instance, validated_data)
        instance['their_did'] = validated_data.get('their_did')


class DIDSerializer(serializers.Serializer):

    did = serializers.CharField(max_length=1024, required=True)

    def create(self, validated_data):
        return dict(validated_data)

    def update(self, instance, validated_data):
        super().update(instance, validated_data)
        instance['did'] = validated_data.get('did')


class DIDCreateSerializer(WalletAccessSerializer):

    did = serializers.CharField(max_length=1024, required=False)
    verkey = serializers.CharField(max_length=1024, required=False)
    seed = serializers.CharField(max_length=1024, required=False)

    def update(self, instance, validated_data):
        super().update(instance, validated_data)
        instance['did'] = validated_data.get('did')
        instance['verkey'] = validated_data.get('verkey')
        instance['seed'] = validated_data.get('seed')


class NymRequestSerializer(WalletAccessSerializer):

    target_did = serializers.CharField(max_length=1024, required=True)
    ver_key = serializers.CharField(max_length=1024, required=True)
    alias = serializers.CharField(max_length=1024, required=False, allow_null=True, default=None)
    role = serializers.CharField(required=True, validators=[validate_nym_request_role])

    def update(self, instance, validated_data):
        super().update(instance, validated_data)
        instance['target_did'] = validated_data.get('target_did')
        instance['ver_key'] = validated_data.get('ver_key')
        instance['alias'] = validated_data.get('alias')
        instance['role'] = validated_data.get('role')


class SchemaRegisterSerializer(WalletAccessSerializer):

    name = serializers.CharField(max_length=128, required=True)
    version = serializers.CharField(max_length=36, required=True)
    attributes = serializers.ListField(max_length=128, allow_empty=False, required=True)

    def update(self, instance, validated_data):
        super().update(instance, validated_data)
        instance['name'] = validated_data.get('did')
        instance['version'] = validated_data.get('verkey')
        instance['attributes'] = validated_data.get('seed')


class CredentialDefinitionCreateSerializer(WalletAccessSerializer):

    schema = serializers.JSONField(required=True)
    tag = serializers.CharField(max_length=56, required=True)
    support_revocation = serializers.BooleanField(required=True)

    def update(self, instance, validated_data):
        super().update(instance, validated_data)
        instance['schema'] = validated_data.get('schema')
        instance['tag'] = validated_data.get('tag')
        instance['support_revocation'] = validated_data.get('support_revocation')
