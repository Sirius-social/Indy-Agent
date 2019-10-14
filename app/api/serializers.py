from rest_framework import serializers


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
