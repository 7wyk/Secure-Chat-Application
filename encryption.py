
import os
import json
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

class EncryptionManager:
    """Handles all encryption/decryption operations for the chat application."""
    
    def __init__(self):
        self.backend = default_backend()
        self.rsa_private_key = None
        self.rsa_public_key = None
        self.session_keys = {} 
        
    def generate_rsa_keypair(self):
        """Generate RSA key pair for asymmetric encryption."""
        try:
            self.rsa_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=self.backend
            )
            self.rsa_public_key = self.rsa_private_key.public_key()
            print("✓ RSA keypair generated successfully")
            return True
        except Exception as e:
            print(f"✗ Error generating RSA keypair: {e}")
            return False
    
    def get_public_key_pem(self):
        """Return public key in PEM format for sharing."""
        if not self.rsa_public_key:
            return None
            
        pem = self.rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')
    
    def load_public_key_pem(self, pem_data):
        """Load a public key from PEM format."""
        try:
            return serialization.load_pem_public_key(
                pem_data.encode('utf-8'),
                backend=self.backend
            )
        except Exception as e:
            print(f"✗ Error loading public key: {e}")
            return None
    
    def generate_aes_key(self):
        """Generate a random AES-256 key."""
        return os.urandom(32)  
    
    def encrypt_aes_key_with_rsa(self, aes_key, public_key_pem):
        """Encrypt AES key using RSA public key."""
        try:
            public_key = self.load_public_key_pem(public_key_pem)
            if not public_key:
                return None
                
            encrypted_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return base64.b64encode(encrypted_key).decode('utf-8')
        except Exception as e:
            print(f"✗ Error encrypting AES key with RSA: {e}")
            return None
    
    def decrypt_aes_key_with_rsa(self, encrypted_key_b64):
        """Decrypt AES key using RSA private key."""
        try:
            if not self.rsa_private_key:
                return None
                
            encrypted_key = base64.b64decode(encrypted_key_b64.encode('utf-8'))
            aes_key = self.rsa_private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return aes_key
        except Exception as e:
            print(f"✗ Error decrypting AES key with RSA: {e}")
            return None
    
    def encrypt_message_aes(self, message, aes_key):
        """Encrypt message using AES-GCM."""
        try:
           
            nonce = os.urandom(12)
            
        
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(nonce),
                backend=self.backend
            )
            encryptor = cipher.encryptor()
            
           
            message_bytes = message.encode('utf-8')
            ciphertext = encryptor.update(message_bytes) + encryptor.finalize()
            
           
            encrypted_data = nonce + encryptor.tag + ciphertext
            return base64.b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            print(f"✗ Error encrypting message: {e}")
            return None
    
    def decrypt_message_aes(self, encrypted_message_b64, aes_key):
        """Decrypt message using AES-GCM."""
        try:
            
            encrypted_data = base64.b64decode(encrypted_message_b64.encode('utf-8'))
            
           
            nonce = encrypted_data[:12]     
            tag = encrypted_data[12:28]     
            ciphertext = encrypted_data[28:] 
            
            
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(nonce, tag),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            
          
            message_bytes = decryptor.update(ciphertext) + decryptor.finalize()
            return message_bytes.decode('utf-8')
            
        except Exception as e:
            print(f"✗ Error decrypting message: {e}")
            return None
    
    def create_session_key(self, conversation_id):
        """Create and store a session key for a conversation."""
        session_key = self.generate_aes_key()
        self.session_keys[conversation_id] = session_key
        return session_key
    
    def get_session_key(self, conversation_id):
        """Get existing session key for a conversation."""
        return self.session_keys.get(conversation_id)
    
    def remove_session_key(self, conversation_id):
        """Remove session key for a conversation (forward secrecy)."""
        if conversation_id in self.session_keys:
            del self.session_keys[conversation_id]
            
    def secure_delete_keys(self):
        """Securely delete all keys from memory."""
        self.session_keys.clear()
        self.rsa_private_key = None
        self.rsa_public_key = None
        print("✓ All encryption keys cleared from memory")

class MessagePacket:
    """Structure for encrypted message packets."""
    
    def __init__(self, sender=None, recipient=None, message_type="text", 
                 encrypted_content=None, encrypted_key=None, timestamp=None):
        self.sender = sender
        self.recipient = recipient
        self.message_type = message_type
        self.encrypted_content = encrypted_content
        self.encrypted_key = encrypted_key
        self.timestamp = timestamp
    
    def to_json(self):
        """Convert packet to JSON for transmission."""
        return json.dumps({
            'sender': self.sender,
            'recipient': self.recipient,
            'message_type': self.message_type,
            'encrypted_content': self.encrypted_content,
            'encrypted_key': self.encrypted_key,
            'timestamp': self.timestamp
        })
    
    @classmethod
    def from_json(cls, json_str):
        """Create packet from JSON data."""
        try:
            data = json.loads(json_str)
            return cls(
                sender=data.get('sender'),
                recipient=data.get('recipient'),
                message_type=data.get('message_type', 'text'),
                encrypted_content=data.get('encrypted_content'),
                encrypted_key=data.get('encrypted_key'),
                timestamp=data.get('timestamp')
            )
        except Exception as e:
            print(f"✗ Error parsing message packet: {e}")
            return None
