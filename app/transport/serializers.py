from rest_framework import serializers

from .models import Endpoint


class EndpointSerializer(serializers.ModelSerializer):

    class Meta:
        model = Endpoint
        fields = ('uid',)
