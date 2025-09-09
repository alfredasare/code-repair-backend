import os
import json
from typing import Dict, Any
from cryptography.fernet import Fernet
from app.core.config import settings


class CredentialEncryption:
    """Handles encryption and decryption of sensitive credentials"""
    
    def __init__(self):
        # In production, get this from a secure environment variable
        # For now, generate a key if one doesn't exist
        self.encryption_key = self._get_or_create_encryption_key()
        self.cipher_suite = Fernet(self.encryption_key)
    
    def _get_or_create_encryption_key(self) -> bytes:
        """Get encryption key from environment or create a new one"""
        key_str = getattr(settings, 'credential_encryption_key', None)
        
        if key_str:
            return key_str.encode()
        else:
            # Generate a new key (in production, this should be set in environment)
            new_key = Fernet.generate_key()
            print(f"WARNING: Generated new encryption key. Set CREDENTIAL_ENCRYPTION_KEY={new_key.decode()} in your environment.")
            return new_key
    
    def encrypt_credentials(self, credentials: Dict[str, Any]) -> str:
        """Encrypt credentials dictionary to string"""
        credentials_json = json.dumps(credentials)
        encrypted_bytes = self.cipher_suite.encrypt(credentials_json.encode())
        return encrypted_bytes.decode()
    
    def decrypt_credentials(self, encrypted_credentials: str) -> Dict[str, Any]:
        """Decrypt credentials string back to dictionary"""
        try:
            decrypted_bytes = self.cipher_suite.decrypt(encrypted_credentials.encode())
            credentials_json = decrypted_bytes.decode()
            return json.loads(credentials_json)
        except Exception as e:
            raise ValueError(f"Failed to decrypt credentials: {str(e)}")


# Global instance
credential_encryption = CredentialEncryption()