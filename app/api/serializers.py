from rest_framework import serializers

from .validators import *


class EmptySerializer(serializers.Serializer):

    def create(self, validated_data):
        return dict(validated_data)

    def update(self, instance, validated_data):
        pass


class WalletAccessSerializer(serializers.Serializer):

    pass_phrase = serializers.CharField(max_length=512, required=False, default='')

    def create(self, validated_data):
        return dict(validated_data)

    def update(self, instance, validated_data):
        instance['pass_phrase'] = validated_data.get('pass_phrase', '')


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


class VerkeySerializer(WalletAccessSerializer):

    their_verkey = serializers.CharField(max_length=1024, required=True)

    def update(self, instance, validated_data):
        super().update(instance, validated_data)
        instance['their_verkey'] = validated_data.get('their_verkey')


class CreatePairwiseSerializer(WalletAccessSerializer):

    my_did = serializers.CharField(max_length=1024, required=True)
    their_did = serializers.CharField(max_length=1024, required=True)
    their_verkey = serializers.CharField(max_length=1024, required=True)
    metadata = serializers.JSONField(required=True)

    def update(self, instance, validated_data):
        super().update(instance, validated_data)
        instance['my_did'] = validated_data.get('my_did')
        instance['their_did'] = validated_data.get('their_did')
        instance['metadata'] = validated_data.get('metadata')


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


class DIDRetrieveSerializer(WalletAccessSerializer):

    did = serializers.CharField(max_length=1024, required=False, default=None, allow_null=True)

    def update(self, instance, validated_data):
        super().update(instance, validated_data)
        instance['did'] = validated_data.get('did')


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


class ProofRequestSerializer(WalletAccessSerializer):

    proof_req = serializers.JSONField(required=True)
    extra_query = serializers.JSONField(required=False, allow_null=True, default=None)

    def update(self, instance, validated_data):
        super().update(instance, validated_data)
        instance['proof_req'] = validated_data.get('proof_req')
        instance['extra_query'] = validated_data.get('extra_query', instance.get('extra_query'))


class CloseSearchHandleSerializer(WalletAccessSerializer):

    search_handle = serializers.IntegerField(required=True)

    def update(self, instance, validated_data):
        super().update(instance, validated_data)
        instance['search_handle'] = validated_data.get('search_handle', instance.get('search_handle'))


class FetchCredForProofRequestSerializer(WalletAccessSerializer):

    search_handle = serializers.IntegerField(required=True)
    item_referent = serializers.CharField(max_length=128, required=True)
    count = serializers.IntegerField(default=1, required=False, min_value=1)

    def update(self, instance, validated_data):
        super().update(instance, validated_data)
        instance['search_handle'] = validated_data.get('search_handle', instance.get('search_handle'))
        instance['item_referent'] = validated_data.get('item_referent', instance.get('item_referent'))
        instance['count'] = validated_data.get('count', instance.get('count'))


class ProverCreateProofSerializer(WalletAccessSerializer):

    proof_req = serializers.JSONField(required=True)
    requested_creds = serializers.JSONField(required=True)
    link_secret_id = serializers.CharField(max_length=128, required=True)
    schemas = serializers.JSONField(required=True)
    cred_defs = serializers.JSONField(required=True)
    rev_states = serializers.JSONField(required=True)

    def update(self, instance, validated_data):
        super().update(instance, validated_data)
        instance['proof_req'] = validated_data.get('proof_req', instance.get('proof_req'))
        instance['requested_creds'] = validated_data.get('requested_creds', instance.get('requested_creds'))
        instance['link_secret_id'] = validated_data.get('link_secret_id', instance.get('link_secret_id'))
        instance['schemas'] = validated_data.get('schemas', instance.get('schemas'))
        instance['cred_defs'] = validated_data.get('cred_defs', instance.get('cred_defs'))
        instance['rev_states'] = validated_data.get('rev_states', instance.get('rev_states'))


class VerifyProofSerializer(EmptySerializer):

    proof_req = serializers.JSONField(required=True)
    proof = serializers.JSONField(required=True)
    schemas = serializers.JSONField(required=True)
    cred_defs = serializers.JSONField(required=True)
    rev_reg_defs = serializers.JSONField(required=True)
    rev_regs = serializers.JSONField(required=True)

    def update(self, instance, validated_data):
        super().update(instance, validated_data)
        instance['proof_req'] = validated_data.get('proof_req', instance.get('proof_req'))
        instance['proof'] = validated_data.get('proof', instance.get('proof'))
        instance['schemas'] = validated_data.get('schemas', instance.get('schemas'))
        instance['cred_defs'] = validated_data.get('cred_defs', instance.get('cred_defs'))
        instance['rev_reg_defs'] = validated_data.get('rev_reg_defs', instance.get('rev_reg_defs'))
        instance['rev_regs'] = validated_data.get('rev_regs', instance.get('rev_regs'))


class LedgerReadSerializer(serializers.Serializer):

    submitter_did = serializers.CharField(max_length=1024, required=False, allow_null=True, default=None)

    def create(self, validated_data):
        return dict(validated_data)

    def update(self, instance, validated_data):
        instance['submitter_did'] = validated_data.get('submitter_did', instance.get('submitter_did'))


class ReadEntitySerializer(LedgerReadSerializer):

    id = serializers.CharField(max_length=1024, required=True)

    def update(self, instance, validated_data):
        instance['id'] = validated_data.get('id', instance.get('id'))


class ReadEntitiesSerializer(LedgerReadSerializer):

    identifiers = serializers.JSONField(required=True)

    def update(self, instance, validated_data):
        instance['identifiers'] = validated_data.get('identifiers', instance.get('identifiers'))


class AnonCryptSerializer(serializers.Serializer):

    message = serializers.JSONField(required=True)
    their_verkey = serializers.CharField(max_length=128, required=True)

    def create(self, validated_data):
        return dict(validated_data)

    def update(self, instance, validated_data):
        instance['message'] = validated_data.get('message', instance.get('message'))
        instance['their_verkey'] = validated_data.get('their_verkey', instance.get('their_verkey'))


class AuthCryptSerializer(AnonCryptSerializer):

    my_verkey = serializers.CharField(max_length=128, required=True)

    def update(self, instance, validated_data):
        instance['my_verkey'] = validated_data.get('my_verkey', instance.get('my_verkey'))


class DecryptSerializer(serializers.Serializer):

    protected = serializers.CharField(required=True)
    iv = serializers.CharField(required=True, max_length=128)
    ciphertext = serializers.CharField(required=True, max_length=128)
    tag = serializers.CharField(required=True, max_length=128)

    def create(self, validated_data):
        return dict(validated_data)

    def update(self, instance, validated_data):
        instance.update(validated_data)


class GetAttributeSerializer(WalletAccessSerializer):

    name = serializers.CharField(required=True, max_length=128)
    target_did = serializers.CharField(max_length=1024, required=True)

    def update(self, instance, validated_data):
        instance.update(validated_data)


class SetAttributeSerializer(GetAttributeSerializer):

    value = serializers.JSONField(required=True)


class BaseMessageSerializer(serializers.Serializer):
    message = serializers.JSONField(required=True)
    extra = serializers.JSONField(required=False, default={})

    def create(self, validated_data):
        return dict(validated_data)

    def update(self, instance, validated_data):
        instance.update(validated_data)


class PeerMessageSerializer(BaseMessageSerializer):
    their_did = serializers.CharField(max_length=1024, required=True)


class EndpointMessageSerializer(BaseMessageSerializer):
    my_verkey = serializers.CharField(max_length=128, required=False, allow_null=True, default=None)
    their_verkey = serializers.CharField(max_length=128, required=True)
    endpoint = serializers.CharField(max_length=1024, required=True)


class ProposedAttribSerializer(serializers.Serializer):

    name = serializers.CharField(max_length=128)
    value = serializers.CharField(max_length=1024)
    mime_type = serializers.CharField(max_length=56, required=False)

    def validate(self, data):
        if 'mime_type' in data:
            mime_type = data.get('mime_type')
            value = data.get('value')
            if not is_base64(value):
                raise ValidationError('value mist be Base64 encoded BLOB for mime_type = "%s"' % mime_type)
        return super().validate(data)

    def create(self, validated_data):
        return dict(validated_data)

    def update(self, instance, validated_data):
        instance['name'] = validated_data.get('name')
        instance['value'] = validated_data.get('value')
        instance['mime_type'] = validated_data.get('mime_type', None)


class AttribTranslationSerializer(serializers.Serializer):
    attrib_name = serializers.CharField(max_length=56)
    translation = serializers.CharField(max_length=56)

    def create(self, validated_data):
        return dict(validated_data)

    def update(self, instance, validated_data):
        instance['attrib_name'] = validated_data.get('attrib_name')
        instance['translation'] = validated_data.get('translation')


class ProposeCredentialSerializer(serializers.Serializer):

    DEF_LOCALE = 'en'

    comment = serializers.CharField(max_length=516, required=False)
    locale = serializers.CharField(
        max_length=16, required=False, default=DEF_LOCALE, help_text='Default: "%s"' % DEF_LOCALE
    )
    proposal_attrib = ProposedAttribSerializer(many=True, required=False)
    schema_id = serializers.CharField(max_length=128, required=False)
    schema_name = serializers.CharField(max_length=56, required=False)
    schema_version = serializers.CharField(max_length=16, required=False)
    schema_issuer_did = serializers.CharField(max_length=56, required=False)
    cred_def_id = serializers.CharField(max_length=56, required=False)
    issuer_did = serializers.CharField(max_length=56, required=False)
    proposal_attrib_translation = AttribTranslationSerializer(many=True, required=False)

    def create(self, validated_data):
        return dict(validated_data)

    def update(self, instance, validated_data):
        super().update(instance, validated_data)
        instance['comment'] = validated_data.get('comment', None)
        instance['locale'] = validated_data.get('locale')
        instance['proposal_attrib'] = validated_data.get('proposal_attrib', None)
        instance['schema_id'] = validated_data.get('schema_id', None)
        instance['schema_name'] = validated_data.get('schema_name', None)
        instance['schema_version'] = validated_data.get('schema_version', None)
        instance['schema_issuer_did'] = validated_data.get('schema_issuer_did', None)
        instance['cred_def_id'] = validated_data.get('cred_def_id', None)
        instance['issuer_did'] = validated_data.get('issuer_did', None)
        instance['proposal_attrib_translation'] = validated_data.get('proposal_attrib_translation', None)


class IssueCredentialSerializer(WalletAccessSerializer):

    DEF_LOCALE = 'en'

    comment = serializers.CharField(max_length=516, required=False)
    locale = serializers.CharField(
        max_length=16, required=False, default=DEF_LOCALE, help_text='Default: "%s"' % DEF_LOCALE
    )
    cred_def_id = serializers.CharField(max_length=128)
    cred_def = serializers.JSONField()
    values = serializers.DictField()
    preview = serializers.DictField(required=False)
    translation = serializers.DictField(required=False)
    their_did = serializers.CharField(max_length=1024)
    rev_reg_id = serializers.CharField(max_length=1024, required=False)

    def update(self, instance, validated_data):
        super().update(instance, validated_data)
        instance['comment'] = validated_data.get('comment', None)
        instance['locale'] = validated_data.get('locale')
        instance['cred_def'] = validated_data.get('cred_def')
        instance['cred_def_id'] = validated_data.get('cred_def_id')
        instance['values'] = validated_data.get('values')
        instance['preview'] = validated_data.get('preview', None)
        instance['translation'] = validated_data.get('translation', None)
        instance['their_did'] = validated_data.get('their_did')
        instance['rev_reg_id'] = validated_data.get('rev_reg_id')


class StopIssueCredentialSerializer(WalletAccessSerializer):

    their_did = serializers.CharField(max_length=1024)

    def update(self, instance, validated_data):
        super().update(instance, validated_data)
        instance['their_did'] = validated_data.get('their_did')
