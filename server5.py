import socket
import threading
import sqlite3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64

# Fernet encryption key (must be the same as the client's)
encryption_key = b'c7mC_8RkZjUF-P4yHNTurkGGRRHrdxLczhQO0JbGb_s='
fernet = Fernet(encryption_key)

# Load RSA private key for decrypting messages
with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(key_file.read(), password=None)

# Load RSA public key for encrypting messages
with open("public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(key_file.read())

clients = []
clients_lock = threading.Lock()

# Initialize the database
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT
        )
    ''')
    conn.commit()
    conn.close()

def register_user(username, password, email):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', (username, password, email))
        conn.commit()
        return "Registration successful"
    except sqlite3.IntegrityError:
        return "Username already exists"
    finally:
        conn.close()

def authenticate_user(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
    user = c.fetchone()
    conn.close()
    return user is not None

def fernet_decrypt(encrypted_message):
    decoded = base64.urlsafe_b64decode(encrypted_message)
    return fernet.decrypt(decoded).decode()

def rsa_decrypt(encrypted_message):
    decoded = base64.urlsafe_b64decode(encrypted_message)
    decrypted = private_key.decrypt(
        decoded,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

def handle_initial_connection(client_socket, addr):
    try:
        encrypted_message = client_socket.recv(1024).decode('utf-8')
        message = fernet_decrypt(encrypted_message)
        if message.startswith("login,"):
            _, username, password = message.split(',')
            if authenticate_user(username, password):
                client_socket.send(fernet.encrypt(b'success').encode('utf-8'))
                with clients_lock:
                    clients.append((client_socket, addr, username))  # Add username to the clients list
                threading.Thread(target=handle_client, args=(client_socket, addr, username)).start()
            else:
                client_socket.send(fernet.encrypt(b'failed').encode('utf-8'))
                client_socket.close()
        elif message.startswith("register,"):
            _, username, password, email = message.split(',')
            response = register_user(username, password, email)
            client_socket.send(fernet.encrypt(response.encode('utf-8')).encode('utf-8'))
        else:
            client_socket.send(fernet.encrypt(b'Invalid command').encode('utf-8'))
            client_socket.close()
    except Exception as e:
        print(f"Error: {str(e)}")
        client_socket.close()

def handle_client(client_socket, addr, username):
    print(f"[*] New connection from {addr} (username: {username})")
    while True:
        try:
            # Read the header to get the message length
            header = client_socket.recv(4)
            if not header:
                break
            message_length = int.from_bytes(header, byteorder='big')

            # Read the complete message
            encrypted_message = b""
            while len(encrypted_message) < message_length:
                part = client_socket.recv(message_length - len(encrypted_message))
                if not part:
                    break
                encrypted_message += part

            if not encrypted_message:
                break

            # Debugging prints on the server side
            print(f"Length of encrypted message received by the server: {len(encrypted_message)}")
            print(f"Encrypted message received by the server: {encrypted_message}")

            # Decrypt the message
            message = rsa_decrypt(encrypted_message)
            print(f"Decrypted message: {message}")

            # Include the sender's info in the message
            sender_info = f"{username}: ".encode('utf-8')
            sender_info_length = len(sender_info)
            sender_info_header = sender_info_length.to_bytes(4, byteorder='big')

            # Broadcast the message to other clients
            broadcast_message(sender_info_header + sender_info + header + encrypted_message, client_socket)
        except ConnectionResetError:
            break
        except Exception as e:
            print(f"Error: {str(e)}")
            break
    with clients_lock:
        clients.remove((client_socket, addr, username))
    client_socket.close()
    print(f"[*] Connection closed from {addr} (username: {username})")

def broadcast_message(message, sender_socket):
    with clients_lock:
        for client_socket, addr, username in clients:
            if client_socket != sender_socket:
                try:
                    print(f"Sending message to {username}")
                    client_socket.send(message)
                except Exception as e:
                    print(f"Error sending message to {username}: {str(e)}")
                    client_socket.close()
                    clients.remove((client_socket, addr, username))

def main():
    init_db()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 9999))  # Listen on all network interfaces
    server.listen(5)
    print("[*] Waiting for connections...")

    while True:
        client_socket, addr = server.accept()
        threading.Thread(target=handle_initial_connection, args=(client_socket, addr)).start()

if __name__ == "__main__":
    main()

