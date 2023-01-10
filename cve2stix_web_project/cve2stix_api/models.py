from django.db import models


class CVE(models.Model):
    cve_id = models.CharField(max_length=20, primary_key=True)
    created = models.DateTimeField()
    modified = models.DateTimeField()
    vulnerability = models.JSONField()

    owner = models.ForeignKey("auth.User", related_name="cves", on_delete=models.CASCADE)