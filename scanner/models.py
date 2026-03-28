from django.db import models
from cryptography.fernet import Fernet
import os
import json

# Generate a key for encryption (in production, store securely)
ENCRYPTION_KEY = os.getenv('NETGUARD_ENCRYPTION_KEY', Fernet.generate_key().decode())
cipher = Fernet(ENCRYPTION_KEY.encode())

class ScanLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    target_ip = models.CharField(max_length=15)
    encrypted_results = models.TextField()  # Encrypted JSON string

    def encrypt_data(self, data):
        json_str = json.dumps(data)
        return cipher.encrypt(json_str.encode()).decode()

    def decrypt_data(self):
        return json.loads(cipher.decrypt(self.encrypted_results.encode()).decode())

    class Meta:
        ordering = ['-timestamp']
