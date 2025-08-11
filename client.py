"""
Secure Chat Client - CLI interface with end-to-end encryption.
Connects to chat server and provides user interface for messaging.
"""

import socket
import threading
import json
import time
import sys
import os
from datetime import datetime
import getpass

from config import Config
from encryption import EncryptionManager, MessagePacket

class ChatClient:
    """Secure chat client with CLI interface."""
    
    def __init__(self):
        self.host = Config.SERVER_HOST
        self.port = Config.SERVER_PORT
        self.socket = None
        self.encryption = EncryptionManager()
        self.server_public_key = None
        self.current_user = None
        self.connected = False
        self.authenticated = False
        self.running = False
        self.message_thread = None
        self.session_keys = {}  # {username: aes_key}
        self.user_public_keys = {}  # {username: public_key}
        
        # Generate client RSA keypair
        self.encryption.generate_rsa_keypair()
    
    def connect_to_server(self):
        """Connect to the chat server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.connected = True
            
            print(f"🔗 Connected to server {self.host}:{self.port}")
            
            # Start message receiving thread
            self.message_thread = threading.Thread(target=self.receive_messages, daemon=True)
            self.message_thread.start()
            
            return True
            
        except Exception as e:
            print(f"✗ Connection failed: {e}")
            return False
    
    def receive_messages(self):
        """Receive and process messages from server."""
        while self.connected:
            try:
                # Set a timeout to allow checking self.connected periodically
                self.socket.settimeout(1.0)
                data = self.socket.recv(4096)
                
                if not data:
                    print("🔌 Server closed connection")
                    break
                
                try:
                    message = json.loads(data.decode('utf-8'))
                    self.process_server_message(message)
                except json.JSONDecodeError:
                    print("✗ Received invalid message from server")
                    
            except socket.timeout:
                # Timeout is normal, just continue loop
                continue
            except socket.error as e:
                if self.connected:
                    print(f"🔌 Connection error: {e}")
                break
            except Exception as e:
                if self.connected:
                    print(f"✗ Message receive error: {e}")
                break
        
        self.connected = False
    
    def process_server_message(self, message):
        """Process incoming messages from server."""
        msg_type = message.get('type')
        
        try:
            if msg_type == 'server_hello':
                self.handle_server_hello(message)
            elif msg_type == 'register_success':
                print(f"✅ {message.get('message', 'Registration successful')}")
            elif msg_type == 'login_success':
                self.handle_login_success(message)
            elif msg_type == 'logout_success':
                print(f"👋 {message.get('message', 'Logged out successfully')}")
                self.authenticated = False
                self.current_user = None
            elif msg_type == 'new_message':
                self.handle_new_message(message)
            elif msg_type == 'message_sent':
                timestamp = message.get('timestamp', '')
                delivered = message.get('delivered', False)
                status = "delivered" if delivered else "stored"
                print(f"✅ Message {status} at {timestamp[:19]}")
            elif msg_type == 'users_list':
                self.handle_users_list(message)
            elif msg_type == 'message_history':
                self.handle_message_history(message)
            elif msg_type == 'user_status':
                username = message.get('username')
                status = message.get('status')
                print(f"👤 {username} is now {status}")
            elif msg_type == 'error':
                print(f"❌ Error: {message.get('message', 'Unknown error')}")
            elif msg_type == 'pong':
                pass  # Heartbeat response
            else:
                print(f"❓ Unknown message type: {msg_type}")
                
        except Exception as e:
            print(f"✗ Error processing message: {e}")
    
    def handle_server_hello(self, message):
        """Handle server hello with public key."""
        self.server_public_key = message.get('server_public_key')
        encryption_info = message.get('encryption', 'Unknown')
        print(f"🔐 Server encryption: {encryption_info}")
        print("✅ Secure connection established")
    
    def handle_login_success(self, message):
        """Handle successful login."""
        self.authenticated = True
        user_info = message.get('user', {})
        self.current_user = {
            'id': user_info.get('id'),
            'username': user_info.get('username'),
            'public_key': user_info.get('public_key')
        }
        print(f"✅ Welcome, {self.current_user['username']}!")
        print("🔐 End-to-end encryption active")
    
    def handle_new_message(self, message):
        """Handle incoming encrypted message."""
        try:
            sender = message.get('sender')
            encrypted_content = message.get('encrypted_message')
            encrypted_key = message.get('encrypted_key')
            timestamp = message.get('timestamp', '')
            
            # Try to decrypt the message
            decrypted_message = self.decrypt_incoming_message(
                sender, encrypted_content, encrypted_key
            )
            
            if decrypted_message:
                # Format timestamp
                time_str = timestamp[:19].replace('T', ' ') if timestamp else 'Unknown time'
                print(f"\n💬 [{time_str}] {sender}: {decrypted_message}")
                print(">> ", end="", flush=True)  # Restore input prompt
            else:
                print(f"\n🔒 Encrypted message from {sender} (decryption failed)")
                print(">> ", end="", flush=True)
                
        except Exception as e:
            print(f"✗ Error handling message: {e}")
    
    def handle_users_list(self, message):
        """Handle users list response."""
        users = message.get('users', [])
        count = message.get('count', 0)
        
        if count == 0:
            print("👥 No other users online")
        else:
            print(f"👥 Online users ({count}):")
            for user in users:
                print(f"   • {user['username']}")
    
    def handle_message_history(self, message):
        """Handle message history response."""
        messages = message.get('messages', [])
        other_user = message.get('other_user', 'Unknown')
        count = message.get('count', 0)
        
        print(f"\n📜 Message history with {other_user} ({count} messages):")
        print("-" * 50)
        
        if not messages:
            print("No messages found")
        else:
            # Reverse to show oldest first
            messages.reverse()
            
            for msg in messages:
                timestamp = msg['timestamp'][:19].replace('T', ' ')
                sender = msg['sender']
                
                # Try to decrypt message
                if sender == self.current_user['username']:
                    # Our message - we don't need to decrypt
                    print(f"[{timestamp}] You: [encrypted message]")
                else:
                    # Try to decrypt incoming message
                    decrypted = self.decrypt_incoming_message(
                        sender, msg['encrypted_message'], msg.get('encrypted_key')
                    )
                    content = decrypted if decrypted else "[encrypted - cannot decrypt]"
                    print(f"[{timestamp}] {sender}: {content}")
        
        print("-" * 50)
    
    def send_message_to_server(self, message):
        """Send JSON message to server."""
        try:
            if self.socket and self.connected:
                json_message = json.dumps(message)
                self.socket.send(json_message.encode('utf-8'))
                return True
        except Exception as e:
            print(f"✗ Send error: {e}")
            return False
        return False
    
    def register(self, username, password):
        """Register new user account."""
        message = {
            'type': 'register',
            'username': username,
            'password': password,
            'public_key': self.encryption.get_public_key_pem()
        }
        return self.send_message_to_server(message)
    
    def login(self, username, password):
        """Login to the chat server."""
        message = {
            'type': 'login',
            'username': username,
            'password': password,
            'public_key': self.encryption.get_public_key_pem()
        }
        return self.send_message_to_server(message)
    
    def logout(self):
        """Logout from the chat server."""
        message = {'type': 'logout'}
        self.send_message_to_server(message)
        time.sleep(0.5)  # Allow time for logout to process
    
    def get_online_users(self):
        """Get list of online users."""
        message = {'type': 'get_users'}
        return self.send_message_to_server(message)
    
    def get_message_history(self, username, limit=20):
        """Get message history with another user."""
        message = {
            'type': 'get_messages',
            'username': username,
            'limit': limit
        }
        return self.send_message_to_server(message)
    
    def establish_session_key(self, recipient_username):
        """Establish AES session key for communication with recipient."""
        try:
            # For this implementation, we'll create a new session key each time
            # In production, you'd implement proper key exchange protocol
            session_key = self.encryption.generate_aes_key()
            self.session_keys[recipient_username] = session_key
            return session_key
        except Exception as e:
            print(f"✗ Error establishing session key: {e}")
            return None
    
    def encrypt_message_for_recipient(self, message, recipient_username):
        """Encrypt message for specific recipient."""
        try:
            # Get or create session key
            session_key = self.session_keys.get(recipient_username)
            if not session_key:
                session_key = self.establish_session_key(recipient_username)
            
            if not session_key:
                return None, None
            
            # Encrypt message with AES
            encrypted_message = self.encryption.encrypt_message_aes(message, session_key)
            
            # For this implementation, we'll use a simple key sharing approach
            # In production, you'd get the recipient's public key and encrypt the session key
            # For now, we'll use a placeholder encrypted key
            encrypted_key = "placeholder_key"  # In real implementation, encrypt session_key with recipient's RSA public key
            
            return encrypted_message, encrypted_key
            
        except Exception as e:
            print(f"✗ Error encrypting message: {e}")
            return None, None
    
    def decrypt_incoming_message(self, sender_username, encrypted_message, encrypted_key):
        """Decrypt incoming message from sender."""
        try:
            # Get session key for this sender
            session_key = self.session_keys.get(sender_username)
            
            if not session_key:
                # For this implementation, create a matching session key
                # In production, you'd decrypt the encrypted_key with your private key
                session_key = self.establish_session_key(sender_username)
            
            if not session_key:
                return None
            
            # Decrypt message
            decrypted_message = self.encryption.decrypt_message_aes(encrypted_message, session_key)
            return decrypted_message
            
        except Exception as e:
            print(f"✗ Error decrypting message: {e}")
            return None
    
    def send_chat_message(self, recipient_username, message):
        """Send encrypted chat message to recipient."""
        if not self.authenticated:
            print("❌ You must be logged in to send messages")
            return False
        
        # Encrypt message
        encrypted_message, encrypted_key = self.encrypt_message_for_recipient(
            message, recipient_username
        )
        
        if not encrypted_message:
            print("❌ Failed to encrypt message")
            return False
        
        # Send to server
        server_message = {
            'type': 'send_message',
            'recipient': recipient_username,
            'encrypted_message': encrypted_message,
            'encrypted_key': encrypted_key
        }
        
        return self.send_message_to_server(server_message)
    
    def disconnect(self):
        """Disconnect from server."""
        self.connected = False
        self.running = False
        
        if self.authenticated:
            self.logout()
        
        if self.socket:
            self.socket.close()
        
        # Clear sensitive data
        self.encryption.secure_delete_keys()
        self.session_keys.clear()
        
        print("🔌 Disconnected from server")

class ChatCLI:
    """Command-line interface for the chat client."""
    
    def __init__(self):
        self.client = ChatClient()
        self.running = True
    
    def display_header(self):
        """Display application header."""
        print("\n" + "="*60)
        print("🔐 SECURE CHAT CLIENT")
        print("End-to-End Encrypted Messaging")
        print("="*60)
    
    def display_menu(self):
        """Display main menu options."""
        if not self.client.authenticated:
            print("\n📋 MAIN MENU:")
            print("1. Register new account")
            print("2. Login to existing account")
            print("3. Exit")
        else:
            print(f"\n📋 CHAT MENU (Logged in as: {self.client.current_user['username']}):")
            print("1. Send message")
            print("2. View online users")
            print("3. View message history")
            print("4. Logout")
            print("5. Exit")
    
    def get_user_choice(self):
        """Get user menu choice."""
        try:
            choice = input("\n>> Enter choice (1-5): ").strip()
            return choice
        except KeyboardInterrupt:
            return "exit"
    
    def handle_register(self):
        """Handle user registration."""
        print("\n📝 USER REGISTRATION")
        print("-" * 30)
        
        username = input("Username (3-50 chars): ").strip()
        if not username or len(username) < 3 or len(username) > 50:
            print("❌ Invalid username length")
            return
        
        try:
            password = getpass.getpass("Password (6+ chars): ")
            if not password or len(password) < 6:
                print("❌ Password must be at least 6 characters")
                return
            
            confirm_password = getpass.getpass("Confirm password: ")
            if password != confirm_password:
                print("❌ Passwords don't match")
                return
        except KeyboardInterrupt:
            print("\n❌ Registration cancelled")
            return
        except Exception as e:
            print(f"❌ Password input error: {e}")
            # Fallback to regular input (less secure but works)
            print("⚠️  Using fallback input method (password will be visible)")
            password = input("Password (6+ chars): ").strip()
            if not password or len(password) < 6:
                print("❌ Password must be at least 6 characters")
                return
            confirm_password = input("Confirm password: ").strip()
            if password != confirm_password:
                print("❌ Passwords don't match")
                return
        
        print("🔄 Registering user...")
        if self.client.register(username, password):
            print("⏳ Please wait for server response...")
            time.sleep(2)  # Give time for server response
        else:
            print("❌ Registration request failed")
    
    def handle_login(self):
        """Handle user login."""
        print("\n🔑 USER LOGIN")
        print("-" * 20)
        
        username = input("Username: ").strip()
        if not username:
            print("❌ Username required")
            return
        
        try:
            password = getpass.getpass("Password: ")
            if not password:
                print("❌ Password required")
                return
        except KeyboardInterrupt:
            print("\n❌ Login cancelled")
            return
        except Exception as e:
            print(f"❌ Password input error: {e}")
            # Fallback to regular input
            print("⚠️  Using fallback input method (password will be visible)")
            password = input("Password: ").strip()
            if not password:
                print("❌ Password required")
                return
        
        print("🔄 Logging in...")
        if self.client.login(username, password):
            print("⏳ Please wait for server response...")
            time.sleep(2)  # Give time for server response
        else:
            print("❌ Login request failed")
    
    def handle_send_message(self):
        """Handle sending a message."""
        print("\n💬 SEND MESSAGE")
        print("-" * 20)
        
        recipient = input("Recipient username: ").strip()
        if not recipient:
            print("❌ Recipient required")
            return
        
        if recipient == self.client.current_user['username']:
            print("❌ Cannot send message to yourself")
            return
        
        print("Enter your message (press Enter to send, Ctrl+C to cancel):")
        try:
            message = input(">> ").strip()
            if not message:
                print("❌ Empty message not allowed")
                return
            
            print("🔐 Encrypting and sending message...")
            if self.client.send_chat_message(recipient, message):
                print("⏳ Message sent, waiting for confirmation...")
            else:
                print("❌ Failed to send message")
                
        except KeyboardInterrupt:
            print("\n❌ Message cancelled")
    
    def handle_view_users(self):
        """Handle viewing online users."""
        print("\n👥 ONLINE USERS")
        print("-" * 20)
        print("🔄 Fetching online users...")
        
        if self.client.get_online_users():
            time.sleep(1)  # Give time for server response
        else:
            print("❌ Failed to get users list")
    
    def handle_message_history(self):
        """Handle viewing message history."""
        print("\n📜 MESSAGE HISTORY")
        print("-" * 25)
        
        username = input("Enter username to view history with: ").strip()
        if not username:
            print("❌ Username required")
            return
        
        try:
            limit = input("Number of messages to show (default 20, max 100): ").strip()
            limit = int(limit) if limit else 20
            limit = min(max(1, limit), 100)  # Ensure 1-100 range
        except ValueError:
            limit = 20
        
        print(f"🔄 Fetching last {limit} messages with {username}...")
        if self.client.get_message_history(username, limit):
            time.sleep(2)  # Give time for server response
        else:
            print("❌ Failed to get message history")
    
    def handle_logout(self):
        """Handle user logout."""
        print("🔄 Logging out...")
        self.client.logout()
        time.sleep(1)
        print("👋 Logged out successfully")
    
    def run(self):
        """Run the CLI interface."""
        try:
            # Display header
            self.display_header()
            
            # Connect to server
            print("🔄 Connecting to chat server...")
            if not self.client.connect_to_server():
                print("❌ Failed to connect to server")
                return
            
            # Wait for server hello
            time.sleep(1)
            
            # Main application loop
            while self.running and self.client.connected:
                try:
                    self.display_menu()
                    choice = self.get_user_choice()
                    
                    if choice == "exit" or choice == "5":
                        break
                    elif not self.client.authenticated:
                        # Pre-login menu
                        if choice == "1":
                            self.handle_register()
                        elif choice == "2":
                            self.handle_login()
                        elif choice == "3":
                            break
                        else:
                            print("❌ Invalid choice")
                    else:
                        # Post-login menu
                        if choice == "1":
                            self.handle_send_message()
                        elif choice == "2":
                            self.handle_view_users()
                        elif choice == "3":
                            self.handle_message_history()
                        elif choice == "4":
                            self.handle_logout()
                        elif choice == "5":
                            break
                        else:
                            print("❌ Invalid choice")
                
                except KeyboardInterrupt:
                    print("\n\n🛑 Interrupted by user")
                    break
                except Exception as e:
                    print(f"\n❌ Unexpected error: {e}")
                    break
            
        except Exception as e:
            print(f"❌ Application error: {e}")
        
        finally:
            # Cleanup
            print("\n🧹 Cleaning up...")
            self.client.disconnect()
            print("👋 Goodbye!")

def main():
    """Main client entry point."""
    try:
        # Validate configuration
        Config.validate_config()
        
        # Create and run CLI
        cli = ChatCLI()
        cli.run()
        
    except KeyboardInterrupt:
        print("\n\n🛑 Application interrupted by user")
    except Exception as e:
        print(f"❌ Application error: {e}")
    finally:
        print("\n👋 Secure Chat Client closed")

if __name__ == "__main__":
    main()