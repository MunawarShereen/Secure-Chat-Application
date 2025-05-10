import socket
import threading
import json
import os
import base64
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2

# Server configuration
HOST = '127.0.0.1'
PORT = 12345
BUFFER_SIZE = 4096

# User database file
USER_DB = 'user_db.json'

# Initialize empty user database if it doesn't exist
if not os.path.exists(USER_DB):
    with open(USER_DB, 'w') as f:
        json.dump({}, f)

# Active clients dictionary {username: (connection, address, session_key)}
active_clients = {}

# Lock for thread-safe operations
lock = threading.Lock()

def load_users():
    try:
        with open(USER_DB, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_users(users):
    with open(USER_DB, 'w') as f:
        json.dump(users, f, indent=4)

def register_user(username, password):
    users = load_users()
    if username in users:
        return False, "Username already exists"
    
    # Generate salt and hash the password
    salt = os.urandom(16)
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    users[username] = {
        'salt': base64.b64encode(salt).decode('utf-8'),
        'key': base64.b64encode(key).decode('utf-8')
    }
    
    save_users(users)
    return True, "Registration successful"

def authenticate_user(username, password):
    users = load_users()
    if username not in users:
        return False, None, "Invalid username"
    
    user_data = users[username]
    salt = base64.b64decode(user_data['salt'].encode('utf-8'))
    stored_key = base64.b64decode(user_data['key'].encode('utf-8'))
    
    # Derive key from provided password
    derived_key = PBKDF2(password, salt, dkLen=32, count=100000)
    
    if derived_key == stored_key:
        # Generate a new session key for this login
        session_key = os.urandom(32)
        return True, session_key, "Authentication successful"
    else:
        return False, None, "Invalid password"

def pad_message(message):
    # PKCS7 padding for AES
    pad_length = AES.block_size - (len(message) % AES.block_size)
    return message + bytes([pad_length] * pad_length)

def unpad_message(padded_message):
    # Remove PKCS7 padding
    pad_length = padded_message[-1]
    return padded_message[:-pad_length]

def encrypt_message(message, key):
    # Generate a random IV for each message
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad_message(message)
    ciphertext = cipher.encrypt(padded_message)
    return iv + ciphertext

def decrypt_message(encrypted_message, key):
    # Extract IV from the first 16 bytes
    iv = encrypted_message[:AES.block_size]
    ciphertext = encrypted_message[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = cipher.decrypt(ciphertext)
    return unpad_message(padded_message)

def broadcast_message(sender_username, message):
    with lock:
        for username, (conn, addr, session_key) in active_clients.items():
            if username != sender_username:
                try:
                    encrypted_msg = encrypt_message(message.encode('utf-8'), session_key)
                    conn.sendall(encrypted_msg)
                except Exception as e:
                    print(f"Error broadcasting to {username}: {e}")
                    if username in active_clients:
                        del active_clients[username]

def handle_client(conn, addr):
    print(f"New connection from {addr}")
    username = None
    
    try:
        while True:
            # Authentication phase
            auth_data = conn.recv(BUFFER_SIZE).decode('utf-8').strip()
            if not auth_data:
                break
                
            if ':' not in auth_data:
                conn.sendall("Invalid format".encode('utf-8'))
                continue
                
            action, *rest = auth_data.split(':', 2)
            
            if action == 'register':
                if len(rest) != 2:
                    conn.sendall("Invalid registration format".encode('utf-8'))
                    continue
                    
                username, password = rest
                success, message = register_user(username, password)
                conn.sendall(message.encode('utf-8'))
                if not success:
                    continue
                    
            elif action == 'login':
                if len(rest) != 2:
                    conn.sendall("Invalid login format".encode('utf-8'))
                    continue
                    
                username, password = rest
                success, session_key, message = authenticate_user(username, password)
                if not success:
                    conn.sendall(message.encode('utf-8'))
                    continue
                    
                # Send success message and session key
                conn.sendall(base64.b64encode(session_key).decode('utf-8').encode('utf-8'))
                
                # Add client to active clients
                with lock:
                    active_clients[username] = (conn, addr, session_key)
                
                # Main chat loop
                while True:
                    try:
                        encrypted_msg = conn.recv(BUFFER_SIZE)
                        if not encrypted_msg:
                            break
                            
                        decrypted_msg = decrypt_message(encrypted_msg, session_key)
                        message = decrypted_msg.decode('utf-8')
                        
                        if message.lower() == '/exit':
                            break
                            
                        print(f"Received from {username}: {message}")
                        broadcast_message(username, f"{username}: {message}")
                    except Exception as e:
                        print(f"Error with client {username}: {e}")
                        break
                        
                # Remove client when they exit
                with lock:
                    if username in active_clients:
                        del active_clients[username]
                break
                
            else:
                conn.sendall("Invalid action".encode('utf-8'))
                
    except Exception as e:
        print(f"Error with client {addr}: {e}")
    finally:
        if username in active_clients:
            with lock:
                del active_clients[username]
        conn.close()
        print(f"Connection with {addr} closed")

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"Server started on {HOST}:{PORT}")
    
    try:
        while True:
            conn, addr = server_socket.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()
    except KeyboardInterrupt:
        print("Shutting down server...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()