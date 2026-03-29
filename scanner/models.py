from django.conf import settings
from django.db import models
from cryptography.fernet import Fernet
import os
import json

ENCRYPTION_KEY = os.getenv('NETGUARD_ENCRYPTION_KEY', Fernet.generate_key().decode())
cipher = Fernet(ENCRYPTION_KEY.encode())


class ScanLog(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='scan_logs',
        null=True,
        blank=True,
    )
    timestamp = models.DateTimeField(auto_now_add=True)
    target_ip = models.CharField(max_length=45)
    target_label = models.CharField(max_length=255, blank=True)
    status = models.CharField(max_length=32, default='completed')
    risk_score = models.PositiveSmallIntegerField(default=0)
    open_port_count = models.PositiveIntegerField(default=0)
    critical_count = models.PositiveIntegerField(default=0)
    os_detected = models.CharField(max_length=255, blank=True)
    encrypted_results = models.TextField()

    def encrypt_data(self, data):
        json_str = json.dumps(data)
        return cipher.encrypt(json_str.encode()).decode()

    def decrypt_data(self):
        return json.loads(cipher.decrypt(self.encrypted_results.encode()).decode())

    def summary(self):
        return {
            'id': self.id,
            'target_ip': self.target_ip,
            'target_label': self.target_label or self.target_ip,
            'status': self.status,
            'risk_score': self.risk_score,
            'open_port_count': self.open_port_count,
            'critical_count': self.critical_count,
            'os_detected': self.os_detected,
            'timestamp': self.timestamp.isoformat(),
        }

    class Meta:
        ordering = ['-timestamp']