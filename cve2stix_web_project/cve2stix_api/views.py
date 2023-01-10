from cve2stix_api.models import CVE
from cve2stix_api.serializers import CVESerializer
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
            else:
                print(serializer.errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as ex:
            print(ex)


# class CVEDetail(APIView):
#     """
#     Retrieve or 
#     """