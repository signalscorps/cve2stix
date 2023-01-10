from cve2stix_api.models import CVE
from cve2stix_api.serializers import CVESerializer
from django.http import Http404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import permissions


class CVEList(APIView):
    """
    List all CVEs, or create a CVE
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, format=None):
        cves = CVE.objects.all()
        serializer = CVESerializer(cves, many=True)
        return Response(serializer.data)
    
    def post(self, request, format=None):
        try:
            serializer = CVESerializer(data=request.data)
            if serializer.is_valid():
                serializer.save(owner=self.request.user)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as ex:
            print(ex)


class CVEDetail(APIView):
    """
    Retrieve, update or delete an existing CVE
    """

    def get_cve_object(self, cve_id):
        try:
            return CVE.objects.get(cve_id=cve_id)
        except CVE.DoesNotExist:
            raise Http404
    
    def get(self, request, cve_id, format=None):
        cve = self.get_cve_object(cve_id)
        serializer = CVESerializer(cve)
        return Response(serializer.data)

    def put(self, request, cve_id, format=None):
        cve = self.get_cve_object(cve_id)
        serializer = CVESerializer(cve, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, cve_id, format=None):
        snippet = self.get_cve_object(cve_id)
        snippet.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
