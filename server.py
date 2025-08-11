"""
Secure Chat Server - Multi-threaded TCP server with encryption support.
Handles client connections, user authentication, and message routing.
"""

import socket
import threading
import json
import time
from datetime import datetime, timezone
import signal
import sys

from config import Config
from database import DatabaseManager
from encryption import EncryptionManager, MessagePacket

class ChatServer:
    """Multi-threaded secure chat server."""
    
    def __init__(self):
        self.host = Config.SERVER_HOST
        self.port = Config.SERVER_PORT
        self.socket = None
        self.clients = {}  # {socket: client_info}
        self.user_sockets = {}  # {user_id: socket}
        self.db = DatabaseManager()
        self.encryption = EncryptionManager()
        self.running = False
        self.client_threads = []
        
        # Generate server RSA keypair for secure communications
        self.encryption.generate_rsa_keypair()
        
        # Setup graceful shutdown
        signal.signal(signal.SIGINT, self.shutdown_handler)
        signal.signal(signal.SIGTERM, self.shutdown_handler)
    
    def start_server(self):
        """Start the chat server."""
        try:
            # Create socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind and listen
            self.socket.bind((self.host, self.port))
            self.socket.listen(Config.MAX_CLIENTS)
            self.running = True
            
            print(f"🚀 Secure Chat Server started on {self.host}:{self.port}")
            print(f"📊 Max clients: {Config.MAX_CLIENTS}")
            print(f"🔐 Encryption: RSA-2048 + AES-256-GCM")
            print("✅ Server ready for connections...")
            
            # Start cleanup thread
            cleanup_thread = threading.Thread(target=self.periodic_cleanup, daemon=True)
            cleanup_thread.start()
            
            # Accept client connections
            while self.running:
                try:
                    client_socket, address = self.socket.accept()
                    print(f"🔗 New connection from {address}")
                    
                    # Create client thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()
                    self.client_threads.append(client_thread)
                    
                except socket.error:
                    if self.running:
                        print("✗ Error accepting connection")
                        
        except Exception as e:
            print(f"✗ Server startup error: {e}")
        finally:
            self.cleanup()
    
    def handle_client(self, client_socket, address):
        """Handle individual client connection."""
        client_info = {
            'socket': client_socket,
            'address': address,
            'user': None,
            'authenticated': False,
            'last_activity': time.time()
        }
        
        self.clients[client_socket] = client_info
        
        try:
            # Send server public key
            welcome_msg = {
                'type': 'server_hello',
                'server_public_key': self.encryption.get_public_key_pem(),
                'encryption': 'RSA-2048 + AES-256-GCM'
            }
            
            if not self.send_message(client_socket, welcome_msg):
                print(f"✗ Failed to send welcome message to {address}")
                return
            
            # Main message handling loop
            while self.running:
                try:
                    # Receive message with timeout
                    client_socket.settimeout(30.0)
                    data = client_socket.recv(4096)
                    
                    if not data:
                        print(f"🔌 Client {address} disconnected (no data)")
                        break
                    
                    # Update last activity
                    client_info['last_activity'] = time.time()
                    
                    # Parse message
                    try:
                        message = json.loads(data.decode('utf-8'))
                        self.process_message(client_socket, message)
                    except json.JSONDecodeError as e:
                        print(f"✗ Invalid JSON from {address}: {e}")
                        self.send_error(client_socket, "Invalid message format")
                    
                except socket.timeout:
                    # Check if client is still active
                    if time.time() - client_info['last_activity'] > Config.SESSION_TIMEOUT:
                        print(f"⏰ Client {address} timed out")
                        break
                except ConnectionResetError:
                    print(f"🔌 Client {address} connection reset")
                    break
                except BrokenPipeError:
                    print(f"🔌 Client {address} broken pipe")
                    break
                except Exception as e:
                    print(f"✗ Error handling client {address}: {e}")
                    break
                    
        except Exception as e:
            print(f"✗ Client handler error for {address}: {e}")
        finally:
            self.disconnect_client(client_socket)
    
    def process_message(self, client_socket, message):
        """Process incoming client message."""
        msg_type = message.get('type')
        client_info = self.clients.get(client_socket)
        
        if not client_info:
            return
        
        try:
            if msg_type == 'register':
                self.handle_register(client_socket, message)
            elif msg_type == 'login':
                self.handle_login(client_socket, message)
            elif msg_type == 'logout':
                self.handle_logout(client_socket)
            elif msg_type == 'send_message':
                if client_info['authenticated']:
                    self.handle_send_message(client_socket, message)
                else:
                    self.send_error(client_socket, "Authentication required")
            elif msg_type == 'get_users':
                if client_info['authenticated']:
                    self.handle_get_users(client_socket)
                else:
                    self.send_error(client_socket, "Authentication required")
            elif msg_type == 'get_messages':
                if client_info['authenticated']:
                    self.handle_get_messages(client_socket, message)
                else:
                    self.send_error(client_socket, "Authentication required")
            elif msg_type == 'ping':
                self.send_message(client_socket, {'type': 'pong'})
            else:
                self.send_error(client_socket, f"Unknown message type: {msg_type}")
                
        except Exception as e:
            print(f"✗ Error processing message: {e}")
            self.send_error(client_socket, "Server error processing message")
    
    def handle_register(self, client_socket, message):
        """Handle user registration."""
        try:
            username = message.get('username', '').strip()
            password = message.get('password', '')
            public_key = message.get('public_key')
            
            if not username or not password:
                self.send_error(client_socket, "Username and password required")
                return
            
            # Create user in database
            user_data, error_msg = self.db.create_user(username, password, public_key)
            
            if user_data:
                response = {
                    'type': 'register_success',
                    'message': 'Registration successful',
                    'user': {
                        'id': user_data['id'],
                        'username': user_data['username']
                    }
                }
                self.send_message(client_socket, response)
                print(f"✅ User registered: {username}")
            else:
                self.send_error(client_socket, error_msg)
                
        except Exception as e:
            print(f"✗ Registration error: {e}")
            self.send_error(client_socket, "Registration failed")
    
    def handle_login(self, client_socket, message):
        """Handle user login."""
        try:
            username = message.get('username', '').strip()
            password = message.get('password', '')
            public_key = message.get('public_key')
            
            if not username or not password:
                self.send_error(client_socket, "Username and password required")
                return
            
            # Authenticate user
            user_data, error_msg = self.db.authenticate_user(username, password)
            
            if user_data:
                # Update client info
                client_info = self.clients[client_socket]
                client_info['user'] = user_data
                client_info['authenticated'] = True
                self.user_sockets[user_data['id']] = client_socket
                
                # Update public key if provided
                if public_key:
                    self.db.update_user_public_key(user_data['id'], public_key)
                    user_data['public_key'] = public_key
                
                response = {
                    'type': 'login_success',
                    'message': 'Login successful',
                    'user': {
                        'id': user_data['id'],
                        'username': user_data['username'],
                        'public_key': user_data.get('public_key')
                    }
                }
                self.send_message(client_socket, response)
                print(f"✅ User logged in: {username}")
                
                # Notify other users of new online user
                self.broadcast_user_status(user_data['id'], 'online')
                
            else:
                self.send_error(client_socket, error_msg)
                
        except Exception as e:
            print(f"✗ Login error: {e}")
            self.send_error(client_socket, "Login failed")
    
    def handle_logout(self, client_socket):
        """Handle user logout."""
        try:
            client_info = self.clients.get(client_socket)
            if client_info and client_info['authenticated']:
                user = client_info['user']
                
                # Set user offline in database
                self.db.set_user_offline(user['id'])
                
                # Remove from active users
                if user['id'] in self.user_sockets:
                    del self.user_sockets[user['id']]
                
                # Update client info
                client_info['authenticated'] = False
                client_info['user'] = None
                
                # Notify other users
                self.broadcast_user_status(user['id'], 'offline')
                
                response = {'type': 'logout_success', 'message': 'Logged out successfully'}
                self.send_message(client_socket, response)
                print(f"👋 User logged out: {user['username']}")
                
        except Exception as e:
            print(f"✗ Logout error: {e}")
    
    def handle_send_message(self, client_socket, message):
        """Handle sending messages between users."""
        try:
            client_info = self.clients[client_socket]
            sender = client_info['user']
            
            recipient_username = message.get('recipient')
            encrypted_content = message.get('encrypted_message')
            encrypted_key = message.get('encrypted_key')
            
            if not recipient_username or not encrypted_content:
                self.send_error(client_socket, "Recipient and message content required")
                return
            
            # Get recipient info
            recipient_info = self.db.get_user_public_key(recipient_username)
            if not recipient_info:
                self.send_error(client_socket, "Recipient not found")
                return
            
            # Store message in database
            message_record = self.db.store_message(
                sender['id'],
                recipient_info['id'],
                encrypted_content,
                encrypted_key,
                'direct'
            )
            
            if message_record:
                # Try to deliver message if recipient is online
                recipient_socket = self.user_sockets.get(recipient_info['id'])
                if recipient_socket and recipient_socket in self.clients:
                    delivery_msg = {
                        'type': 'new_message',
                        'sender': sender['username'],
                        'encrypted_message': encrypted_content,
                        'encrypted_key': encrypted_key,
                        'timestamp': message_record['timestamp'].isoformat(),
                        'message_id': message_record['id']
                    }
                    self.send_message(recipient_socket, delivery_msg)
                
                # Confirm to sender
                response = {
                    'type': 'message_sent',
                    'message_id': message_record['id'],
                    'timestamp': message_record['timestamp'].isoformat(),
                    'delivered': recipient_socket is not None
                }
                self.send_message(client_socket, response)
                
                print(f"📨 Message from {sender['username']} to {recipient_username}")
            else:
                self.send_error(client_socket, "Failed to store message")
                
        except Exception as e:
            print(f"✗ Send message error: {e}")
            self.send_error(client_socket, "Failed to send message")
    
    def handle_get_users(self, client_socket):
        """Get list of online users."""
        try:
            online_users = self.db.get_online_users()
            client_info = self.clients[client_socket]
            current_user_id = client_info['user']['id']
            
            # Filter out current user and format response
            users = []
            for user in online_users:
                if user['id'] != current_user_id:
                    users.append({
                        'id': user['id'],
                        'username': user['username'],
                        'status': 'online'
                    })
            
            response = {
                'type': 'users_list',
                'users': users,
                'count': len(users)
            }
            self.send_message(client_socket, response)
            
        except Exception as e:
            print(f"✗ Get users error: {e}")
            self.send_error(client_socket, "Failed to get users list")
    
    def handle_get_messages(self, client_socket, message):
        """Get message history with another user."""
        try:
            client_info = self.clients[client_socket]
            current_user = client_info['user']
            
            other_username = message.get('username')
            limit = min(message.get('limit', 50), 100)  # Max 100 messages
            
            if not other_username:
                self.send_error(client_socket, "Username required")
                return
            
            # Get other user info
            other_user = self.db.get_user_public_key(other_username)
            if not other_user:
                self.send_error(client_socket, "User not found")
                return
            
            # Get messages between users
            messages = self.db.get_messages_between_users(
                current_user['id'], 
                other_user['id'], 
                limit
            )
            
            # Format messages for response
            formatted_messages = []
            for msg in messages:
                formatted_messages.append({
                    'id': msg['id'],
                    'sender': msg['sender_username'],
                    'recipient': msg['recipient_username'],
                    'encrypted_message': msg['encrypted_message'],
                    'encrypted_key': msg['encrypted_key'],
                    'timestamp': msg['timestamp'].isoformat(),
                    'is_read': msg['is_read']
                })
            
            response = {
                'type': 'message_history',
                'messages': formatted_messages,
                'count': len(formatted_messages),
                'other_user': other_username
            }
            self.send_message(client_socket, response)
            
        except Exception as e:
            print(f"✗ Get messages error: {e}")
            self.send_error(client_socket, "Failed to get messages")
    
    def broadcast_user_status(self, user_id, status):
        """Broadcast user online/offline status to all connected clients."""
        try:
            # Get user info
            with self.db.connection.cursor() as cursor:
                cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
                user = cursor.fetchone()
                
            if not user:
                return
            
            # Broadcast to all authenticated clients
            broadcast_msg = {
                'type': 'user_status',
                'username': user['username'],
                'status': status
            }
            
            for client_socket, client_info in self.clients.items():
                if client_info['authenticated'] and client_info['user']['id'] != user_id:
                    try:
                        self.send_message(client_socket, broadcast_msg)
                    except:
                        pass  # Client may be disconnected
                        
        except Exception as e:
            print(f"✗ Broadcast status error: {e}")
    
    def send_message(self, client_socket, message):
        """Send JSON message to client."""
        try:
            json_message = json.dumps(message)
            client_socket.send(json_message.encode('utf-8'))
            return True
        except Exception as e:
            print(f"✗ Send message error: {e}")
            return False
    
    def send_error(self, client_socket, error_message):
        """Send error message to client."""
        error_msg = {
            'type': 'error',
            'message': error_message,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        self.send_message(client_socket, error_msg)
    
    def disconnect_client(self, client_socket):
        """Clean disconnect of client."""
        try:
            client_info = self.clients.get(client_socket)
            if client_info:
                # If user was authenticated, set offline
                if client_info['authenticated'] and client_info['user']:
                    user = client_info['user']
                    self.db.set_user_offline(user['id'])
                    
                    # Remove from active users
                    if user['id'] in self.user_sockets:
                        del self.user_sockets[user['id']]
                    
                    # Broadcast offline status
                    self.broadcast_user_status(user['id'], 'offline')
                    print(f"🔌 User disconnected: {user['username']}")
                
                # Remove from clients
                del self.clients[client_socket]
            
            # Close socket
            client_socket.close()
            
        except Exception as e:
            print(f"✗ Disconnect client error: {e}")
    
    def periodic_cleanup(self):
        """Periodic cleanup of inactive sessions and expired tokens."""
        while self.running:
            try:
                time.sleep(300)  # Run every 5 minutes
                
                # Cleanup expired sessions
                self.db.cleanup_old_sessions()
                
                # Check for inactive clients
                current_time = time.time()
                inactive_clients = []
                
                for client_socket, client_info in self.clients.items():
                    if current_time - client_info['last_activity'] > Config.SESSION_TIMEOUT:
                        inactive_clients.append(client_socket)
                
                # Disconnect inactive clients
                for client_socket in inactive_clients:
                    print("🧹 Cleaning up inactive client")
                    self.disconnect_client(client_socket)
                    
            except Exception as e:
                print(f"✗ Cleanup error: {e}")
    
    def shutdown_handler(self, signum, frame):
        """Handle graceful shutdown."""
        print("\n🛑 Shutdown signal received...")
        self.cleanup()
        sys.exit(0)
    
    def cleanup(self):
        """Clean up server resources."""
        print("🧹 Cleaning up server resources...")
        self.running = False
        
        # Disconnect all clients
        for client_socket in list(self.clients.keys()):
            self.disconnect_client(client_socket)
        
        # Close server socket
        if self.socket:
            self.socket.close()
        
        # Close database connection
        if self.db:
            self.db.close()
        
        # Clear encryption keys
        self.encryption.secure_delete_keys()
        
        print("✅ Server shutdown complete")

def main():
    """Main server entry point."""
    try:
        # Validate configuration
        Config.validate_config()
        
        # Create and start server
        server = ChatServer()
        server.start_server()
        
    except KeyboardInterrupt:
        print("\n🛑 Server interrupted by user")
    except Exception as e:
        print(f"✗ Server error: {e}")

if __name__ == "__main__":
    main()