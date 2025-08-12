
import psycopg2
from psycopg2 import sql, extras
from datetime import datetime, timezone
import hashlib
import secrets
from config import Config

class DatabaseManager:
    """Manages all database operations with security focus."""
    
    def __init__(self):
        self.connection = None
        self.connect()
    
    def connect(self):
        """Establish secure connection to PostgreSQL database."""
        try:
            self.connection = psycopg2.connect(
                Config.DATABASE_URL,
                sslmode='require',
                cursor_factory=extras.RealDictCursor
            )
            self.connection.autocommit = False  
            print("✓ Database connection established")
            self.create_tables()
            return True
        except Exception as e:
            print(f"✗ Database connection failed: {e}")
            return False
    
    def create_tables(self):
        """Create necessary tables if they don't exist."""
        try:
            with self.connection.cursor() as cursor:
               
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(50) UNIQUE NOT NULL,
                        password_hash VARCHAR(128) NOT NULL,
                        salt VARCHAR(64) NOT NULL,
                        public_key TEXT,
                        is_online BOOLEAN DEFAULT FALSE,
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS messages (
                        id SERIAL PRIMARY KEY,
                        sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                        recipient_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                        encrypted_message TEXT NOT NULL,
                        encrypted_key TEXT,
                        message_type VARCHAR(20) DEFAULT 'direct',
                        is_read BOOLEAN DEFAULT FALSE,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        CONSTRAINT valid_message_type CHECK (message_type IN ('direct', 'group', 'system'))
                    )
                """)
                
               
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS chat_rooms (
                        id SERIAL PRIMARY KEY,
                        room_name VARCHAR(100) UNIQUE NOT NULL,
                        created_by INTEGER REFERENCES users(id) ON DELETE CASCADE,
                        is_active BOOLEAN DEFAULT TRUE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS room_members (
                        id SERIAL PRIMARY KEY,
                        room_id INTEGER REFERENCES chat_rooms(id) ON DELETE CASCADE,
                        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        is_admin BOOLEAN DEFAULT FALSE,
                        UNIQUE(room_id, user_id)
                    )
                """)
                
               
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS user_sessions (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                        session_token VARCHAR(128) UNIQUE NOT NULL,
                        expires_at TIMESTAMP NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
                
                self.connection.commit()
                print("✓ Database tables created successfully")
                
        except Exception as e:
            print(f"✗ Error creating tables: {e}")
            self.connection.rollback()
    
    def hash_password(self, password):
        """Create secure password hash with salt."""
        salt = secrets.token_hex(32)  
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  
        )
        return password_hash.hex(), salt
    
    def verify_password(self, password, stored_hash, salt):
        """Verify password against stored hash."""
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        )
        return password_hash.hex() == stored_hash
    
    def create_user(self, username, password, public_key=None):
        """Create a new user account."""
        try:
            
            if not username or not password:
                return None, "Username and password are required"
            
            if len(username) < 3 or len(username) > 50:
                return None, "Username must be 3-50 characters"
            
            if len(password) < 6:
                return None, "Password must be at least 6 characters"
            
           
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
                if cursor.fetchone():
                    return None, "Username already exists"
                
               
                password_hash, salt = self.hash_password(password)
                
                cursor.execute("""
                    INSERT INTO users (username, password_hash, salt, public_key)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id, username, created_at
                """, (username, password_hash, salt, public_key))
                
                user_data = cursor.fetchone()
                self.connection.commit()
                
                print(f"✓ User created: {username}")
                return user_data, "User created successfully"
                
        except Exception as e:
            self.connection.rollback()
            print(f"✗ Error creating user: {e}")
            return None, f"Error creating user: {str(e)}"
    
    def authenticate_user(self, username, password):
        """Authenticate user login."""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    SELECT id, username, password_hash, salt, public_key
                    FROM users WHERE username = %s
                """, (username,))
                
                user = cursor.fetchone()
                if not user:
                    return None, "Invalid username or password"
                
                if self.verify_password(password, user['password_hash'], user['salt']):
                    
                    cursor.execute("""
                        UPDATE users SET is_online = TRUE, last_seen = CURRENT_TIMESTAMP
                        WHERE id = %s
                    """, (user['id'],))
                    self.connection.commit()
                    
                    return dict(user), "Authentication successful"
                else:
                    return None, "Invalid username or password"
                    
        except Exception as e:
            print(f"✗ Authentication error: {e}")
            return None, "Authentication failed"
    
    def update_user_public_key(self, user_id, public_key):
        """Update user's public key."""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    UPDATE users SET public_key = %s WHERE id = %s
                """, (public_key, user_id))
                self.connection.commit()
                return True
        except Exception as e:
            print(f"✗ Error updating public key: {e}")
            self.connection.rollback()
            return False
    
    def get_user_public_key(self, username):
        """Get user's public key by username."""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    SELECT id, public_key FROM users WHERE username = %s
                """, (username,))
                user = cursor.fetchone()
                return dict(user) if user else None
        except Exception as e:
            print(f"✗ Error getting public key: {e}")
            return None
    
    def store_message(self, sender_id, recipient_id, encrypted_message, 
                     encrypted_key=None, message_type='direct'):
        """Store encrypted message in database."""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO messages (sender_id, recipient_id, encrypted_message, 
                                        encrypted_key, message_type, timestamp)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id, timestamp
                """, (sender_id, recipient_id, encrypted_message, encrypted_key, 
                      message_type, datetime.now(timezone.utc)))
                
                result = cursor.fetchone()
                self.connection.commit()
                return dict(result) if result else None
                
        except Exception as e:
            print(f"✗ Error storing message: {e}")
            self.connection.rollback()
            return None
    
    def get_messages_between_users(self, user1_id, user2_id, limit=50):
        """Get recent messages between two users."""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    SELECT m.id, m.sender_id, m.recipient_id, m.encrypted_message,
                           m.encrypted_key, m.message_type, m.timestamp, m.is_read,
                           s.username as sender_username, r.username as recipient_username
                    FROM messages m
                    JOIN users s ON m.sender_id = s.id
                    JOIN users r ON m.recipient_id = r.id
                    WHERE (m.sender_id = %s AND m.recipient_id = %s)
                       OR (m.sender_id = %s AND m.recipient_id = %s)
                    ORDER BY m.timestamp DESC
                    LIMIT %s
                """, (user1_id, user2_id, user2_id, user1_id, limit))
                
                messages = cursor.fetchall()
                return [dict(msg) for msg in messages] if messages else []
                
        except Exception as e:
            print(f"✗ Error getting messages: {e}")
            return []
    
    def get_online_users(self):
        """Get list of currently online users."""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    SELECT id, username, last_seen
                    FROM users
                    WHERE is_online = TRUE
                    ORDER BY username
                """)
                users = cursor.fetchall()
                return [dict(user) for user in users] if users else []
        except Exception as e:
            print(f"✗ Error getting online users: {e}")
            return []
    
    def set_user_offline(self, user_id):
        """Set user as offline."""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    UPDATE users SET is_online = FALSE, last_seen = CURRENT_TIMESTAMP
                    WHERE id = %s
                """, (user_id,))
                self.connection.commit()
                return True
        except Exception as e:
            print(f"✗ Error setting user offline: {e}")
            self.connection.rollback()
            return False
    
    def cleanup_old_sessions(self):
        """Remove expired sessions."""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    DELETE FROM user_sessions WHERE expires_at < CURRENT_TIMESTAMP
                """)
                deleted = cursor.rowcount
                self.connection.commit()
                if deleted > 0:
                    print(f"✓ Cleaned up {deleted} expired sessions")
        except Exception as e:
            print(f"✗ Error cleaning up sessions: {e}")
            self.connection.rollback()
    
    def close(self):
        """Close database connection."""
        if self.connection:
            self.connection.close()
            print("✓ Database connection closed")
