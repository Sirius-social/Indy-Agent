from rest_framework import serializers

from .models import Wallet


class OpenWalletSerializer(serializers.Serializer):

    name = serializers.CharField(max_length=512, required=True)
    pass_phrase = serializers.CharField(max_length=512, required=True)

    def create(self, validated_data):
        return dict(validated_data)

    def update(self, instance, validated_data):
        instance['name'] = validated_data.get('name')
        instance['pass_phrase'] = validated_data.get('pass_phrase')


class WalletSerializer(serializers.ModelSerializer):

    class Meta:
        model = Wallet
        fields = ('name', 'status')
        read_only_fields = ('status',)
