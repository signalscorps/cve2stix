"""
Code for serializing and deserializinng database instances
into JSON
"""

from rest_framework import serializers
from cve2stix_api.models import CVE


class CVESerializer(serializers.ModelSerializer):
    owner = serializers.ReadOnlyField(source="owner.username")

    class Meta:
        model = CVE
        fields = ["cve_id", "created", "modified", "vulnerability", "owner"]
