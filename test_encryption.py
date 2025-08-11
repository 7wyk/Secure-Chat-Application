#!/usr/bin/env python3
"""
Quick test script to verify encryption functionality.
Run this before starting the server to ensure everything works.
"""

from encryption import EncryptionManager

def test_encryption():
    """Test encryption functionality."""
    print("🧪 Testing encryption functionality...")
    
    # Create encryption manager
    enc = EncryptionManager()
    
    # Test 1: RSA Key Generation
    print("1. Testing RSA key generation...")
    if enc.generate_rsa_keypair():
        print("   ✅ RSA keypair generated")
    else:
        print("   ❌ RSA keypair generation failed")
        return False
    
    # Test 2: Public Key Export
    print("2. Testing public key export...")
    pub_key_pem = enc.get_public_key_pem()
    if pub_key_pem:
        print(f"   ✅ Public key exported ({len(pub_key_pem)} chars)")
    else:
        print("   ❌ Public key export failed")
        return False
    
    # Test 3: AES Key Generation
    print("3. Testing AES key generation...")
    aes_key = enc.generate_aes_key()
    if aes_key and len(aes_key) == 32:
        print(f"   ✅ AES key generated ({len(aes_key)} bytes)")
    else:
        print("   ❌ AES key generation failed")
        return False
    
    # Test 4: AES Message Encryption/Decryption
    print("4. Testing AES message encryption...")
    test_message = "Hello, this is a test message! 🔐"
    encrypted_msg = enc.encrypt_message_aes(test_message, aes_key)
    if encrypted_msg:
        print(f"   ✅ Message encrypted ({len(encrypted_msg)} chars)")
        
        # Test decryption
        decrypted_msg = enc.decrypt_message_aes(encrypted_msg, aes_key)
        if decrypted_msg == test_message:
            print("   ✅ Message decrypted successfully")
        else:
            print(f"   ❌ Decryption failed: got '{decrypted_msg}'")
            return False
    else:
        print("   ❌ Message encryption failed")
        return False
    
    # Test 5: RSA Key Loading
    print("5. Testing RSA key loading...")
    loaded_key = enc.load_public_key_pem(pub_key_pem)
    if loaded_key:
        print("   ✅ Public key loaded successfully")
    else:
        print("   ❌ Public key loading failed")
        return False
    
    print("\n🎉 All encryption tests passed!")
    return True

def test_database():
    """Test database connection."""
    print("\n🧪 Testing database connection...")
    
    try:
        from database import DatabaseManager
        from config import Config
        
        # Test config
        Config.validate_config()
        print("   ✅ Configuration valid")
        
        # Test database connection
        db = DatabaseManager()
        if db.connection:
            print("   ✅ Database connected successfully")
            db.close()
            return True
        else:
            print("   ❌ Database connection failed")
            return False
            
    except Exception as e:
        print(f"   ❌ Database test failed: {e}")
        return False

if __name__ == "__main__":
    print("🔧 Secure Chat - System Tests")
    print("=" * 40)
    
    # Run tests
    encryption_ok = test_encryption()
    database_ok = test_database()
    
    print("\n📊 Test Results:")
    print(f"   Encryption: {'✅ PASS' if encryption_ok else '❌ FAIL'}")
    print(f"   Database:   {'✅ PASS' if database_ok else '❌ FAIL'}")
    
    if encryption_ok and database_ok:
        print("\n🚀 System ready! You can start the server now.")
    else:
        print("\n⚠️  Please fix the issues above before starting the server.")