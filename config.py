
import os
from dotenv import load_dotenv


load_dotenv()

class Config:
 
    SERVER_HOST = os.getenv('SERVER_HOST', 'localhost')
    SERVER_PORT = int(os.getenv('SERVER_PORT', 12345))
    

    DATABASE_URL = os.getenv('DATABASE_URL')
    if not DATABASE_URL:
        raise ValueError("DATABASE_URL environment variable is required")
    

    ENCRYPTION_KEY_SIZE = int(os.getenv('ENCRYPTION_KEY_SIZE', 32))
    RSA_KEY_SIZE = int(os.getenv('RSA_KEY_SIZE', 2048))
    
    
    MAX_MESSAGE_LENGTH = int(os.getenv('MAX_MESSAGE_LENGTH', 1024))
    SESSION_TIMEOUT = int(os.getenv('SESSION_TIMEOUT', 3600)) 
    MAX_CLIENTS = int(os.getenv('MAX_CLIENTS', 100))
    
   
    MESSAGE_RATE_LIMIT = int(os.getenv('MESSAGE_RATE_LIMIT', 60))  
    @classmethod
    def validate_config(cls):
        """Validate that all required configuration is present."""
        if not cls.DATABASE_URL:
            raise ValueError("DATABASE_URL is required")
        
        if cls.SERVER_PORT < 1024 or cls.SERVER_PORT > 65535:
            raise ValueError("SERVER_PORT must be between 1024 and 65535")
        
        if cls.ENCRYPTION_KEY_SIZE not in [16, 24, 32]:
            raise ValueError("ENCRYPTION_KEY_SIZE must be 16, 24, or 32 bytes")
        
        print("✓ Configuration validated successfully")
