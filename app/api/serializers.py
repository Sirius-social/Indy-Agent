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
    role = serializers.CharField(required=True, validators=[validate_nym_request_role], allow_null=True)

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

    schema_id = serializers.CharField(max_length=1024, required=True)
    tag = serializers.CharField(max_length=56, required=True)
    support_revocation = serializers.BooleanField(required=True)

    def update(self, instance, validated_data):
        super().update(instance, validated_data)
        instance['schema_id'] = validated_data.get('schema_id')
        instance['tag'] = validated_data.get('tag')
        instance['support_revocation'] = validated_data.get('support_revocation')


class CreateProverMasterSecretSerializer(WalletAccessSerializer):

    link_secret_name = serializers.CharField(max_length=128, required=True)

    def update(self, instance, validated_data):
        super().update(instance, validated_data)
        instance['link_secret_name'] = validated_data.get('link_secret_name')


class CreateIssuerCredentialOfferSerializer(WalletAccessSerializer):

    cred_def_id = serializers.CharField(max_length=1024, required=True)

    def update(self, instance, validated_data):
        super().update(instance, validated_data)
        instance['cred_def_id'] = validated_data.get('cred_def_id')


class CreateProverCredentialRequestSerializer(WalletAccessSerializer):

    prover_did = serializers.CharField(max_length=1024, required=True)
    cred_offer = serializers.JSONField(required=True)
    cred_def = serializers.JSONField(required=True)
    link_secret_id = serializers.CharField(max_length=128, required=True)

    def update(self, instance, validated_data):
        super().update(instance, validated_data)
        instance['prover_did'] = validated_data.get('prover_did')
        instance['cred_offer'] = validated_data.get('cred_offer')
        instance['cred_def'] = validated_data.get('cred_def')
        instance['link_secret_id'] = validated_data.get('link_secret_id')


class CreateIssuerCredentialSerializer(WalletAccessSerializer):

    cred_offer = serializers.JSONField(required=True)
    cred_req = serializers.JSONField(required=True)
    cred_values = serializers.JSONField(required=True)
    rev_reg_id = serializers.CharField(max_length=512, required=False, allow_null=True, default=None)

    def update(self, instance, validated_data):
        super().update(instance, validated_data)
        instance['cred_offer'] = validated_data.get('cred_offer')
        instance['cred_req'] = validated_data.get('cred_req')
        instance['cred_values'] = validated_data.get('cred_values')
        instance['rev_reg_id'] = validated_data.get('rev_reg_id')


class StoreProverCredentialSerializer(WalletAccessSerializer):

    cred_req_metadata = serializers.JSONField(required=True)
    cred = serializers.JSONField(required=True)
    cred_def = serializers.JSONField(required=True)
    rev_reg_def = serializers.CharField(max_length=512, required=False, allow_null=True, default=None)
    cred_id = serializers.CharField(max_length=512, required=False, allow_null=True, default=None)

    def update(self, instance, validated_data):
        super().update(instance, validated_data)
        instance['cred_req_metadata'] = validated_data.get('cred_req_metadata')
        instance['cred'] = validated_data.get('cred')
        instance['cred_def'] = validated_data.get('cred_def')
        instance['rev_reg_def'] = validated_data.get('rev_reg_def')
        instance['cred_id'] = validated_data.get('cred_id')
