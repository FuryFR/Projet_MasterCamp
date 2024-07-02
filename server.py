import socket
import threading
import sqlite3
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

import datetime
import bcrypt
import smtplib
from email.mime.text import MIMEText
import random

clients = {}
clients_lock = threading.Lock()
room_keys = {str(i): os.urandom(32) for i in range(1, 6)}  # Clés de session pour 5 rooms

# Chemins des fichiers
DB_PATH = '/home/user/Documents/users.db'
KEYS_DIR = '/home/user/Documents/keys/'

OTP_CODES = {}

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(email, otp):
    try:
        msg = MIMEText(f"Your OTP code is: {otp}")
        msg['Subject'] = 'Your OTP Code'
        msg['From'] = 'quietlyentreprise@gmail.com'
        msg['To'] = email

        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login('quietlyentreprise@gmail.com', 'ifjc ekem euzk gkob')
            server.sendmail('quietlyentreprise@gmail.com', [email], msg.as_string())
    except Exception as e:
        print(f"Failed to send OTP email: {str(e)}")


def init_db():
    try:
        conn = sqlite3.connect(DB_PATH)
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
        print("Base de données initialisée avec succès.")
    except Exception as e:
        print(f"Erreur lors de l'initialisation de la base de données: {e}")

def generate_keys(username):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)

    # Sauvegarde de la clé privée
    private_key_path = os.path.join(KEYS_DIR, f"{username}_private_key.pem")
    with open(private_key_path, "wb") as private_key_file:
        private_key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Sauvegarde de la clé publique
    public_key_path = os.path.join(KEYS_DIR, f"{username}_public_key.pem")
    with open(public_key_path, "wb") as public_key_file:
        public_key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print(f"Clés générées pour {username} :\n{private_key_path}\n{public_key_path}")


# Fonction de hachage du mot de passe
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Fonction de vérification du mot de passe
def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password)

# Modification de la fonction d'enregistrement pour inclure le hachage du mot de passe
def register_user(username, password, email):
    hashed_password = hash_password(password)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', (username, hashed_password, email))
        conn.commit()
        generate_keys(username)
        return "Registration successful"
    except sqlite3.IntegrityError:
        return "Username already exists"
    finally:
        conn.close()

def authenticate_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT password, email FROM users WHERE username = ?', (username,))
    result = c.fetchone()
    conn.close()
    if result and check_password(result[0], password):
        email = result[1]
        otp = generate_otp()
        OTP_CODES[username] = otp
        send_otp_email(email, otp)
        return True
    return False

def verify_otp(username, otp):
    return OTP_CODES.get(username) == otp


def load_private_key(username):
    private_key_path = os.path.join(KEYS_DIR, f"{username}_private_key.pem")
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    return private_key

def load_public_key(username):
    public_key_path = os.path.join(KEYS_DIR, f"{username}_public_key.pem")
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key


def send_session_key(client_socket, room):
    try:
        key = room_keys[room]
        client_socket.send(key)
    except Exception as e:
        print(f"Erreur lors de l'envoi de la clé de session: {str(e)}")

def handle_initial_connection(client_socket, addr):
    try:
        message = client_socket.recv(1024).decode('utf-8')
        if message.startswith("LOGIN"):
            _, username, password = message.split()
            if authenticate_user(username, password):
                client_socket.send("OTP required".encode('utf-8'))
                otp_message = client_socket.recv(1024).decode('utf-8')
                if otp_message.startswith("OTP"):
                    _, otp = otp_message.split()
                    if verify_otp(username, otp):
                        client_socket.send("Login successful".encode('utf-8'))
                        handle_room_selection(client_socket, addr, username)
                    else:
                        client_socket.send("OTP verification failed".encode('utf-8'))
                        client_socket.close()
                else:
                    client_socket.send("OTP verification required".encode('utf-8'))
                    client_socket.close()
            else:
                client_socket.send("Login failed".encode('utf-8'))
                client_socket.close()
        elif message.startswith("REGISTER"):
            _, username, password, email = message.split()
            response = register_user(username, password, email)
            client_socket.send(response.encode('utf-8'))
        else:
            client_socket.send("Invalid command".encode('utf-8'))
            client_socket.close()
    except Exception as e:
        print(f"Erreur: {str(e)}")
        client_socket.close()


def handle_room_selection(client_socket, addr, username):
    try:
        client_socket.send("Select room: 1, 2, 3, 4, 5".encode('utf-8'))
        message = client_socket.recv(1024).decode('utf-8')
        if message.startswith("ROOM"):
            _, room = message.split()
            if room not in room_keys:
                client_socket.send("Invalid room selection".encode('utf-8'))
                client_socket.close()
                return

            with clients_lock:
                if room not in clients:
                    clients[room] = []
                clients[room].append((client_socket, addr, username))

            client_socket.send(f"Joined room {room}".encode('utf-8'))
            send_session_key(client_socket, room)
            handle_client(client_socket, addr, username, room)  # Direct call instead of thread
        else:
            client_socket.send("Invalid room selection".encode('utf-8'))
            client_socket.close()
    except Exception as e:
        print(f"Erreur: {str(e)}")
        client_socket.close()

def handle_client(client_socket, addr, username, room):
    print(f"[*] Nouvelle connexion de {addr} (utilisateur: {username}) dans la salle {room}")
    while True:
        try:
            header = client_socket.recv(4)
            if not header:
                break
            message_length = int.from_bytes(header, byteorder='big')
            encrypted_message = b""
            while len(encrypted_message) < message_length:
                part = client_socket.recv(message_length - len(encrypted_message))
                if not part:
                    break
                encrypted_message += part

            if not encrypted_message:
                break

            print(f"Longueur du message chiffré reçu par le serveur : {len(encrypted_message)}")
            print(f"Message chiffré reçu par le serveur : {encrypted_message.hex()}")
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            sender_info = f"{username} ({timestamp})".encode('utf-8')
            sender_info_length = len(sender_info)
            sender_info_header = sender_info_length.to_bytes(4, byteorder='big')

            for client in clients[room]:
                if client[0] != client_socket:
                    try:
                        client[0].send(sender_info_header + sender_info + header + encrypted_message)
                    except Exception as e:
                        print(f"Erreur lors de l'envoi du message à {client[2]} : {str(e)}")
                        client[0].close()
                        clients[room].remove(client)
        except ConnectionResetError:
            break
        except Exception as e:
            print(f"Erreur : {str(e)}")
            break
    with clients_lock:
        clients[room].remove((client_socket, addr, username))
    client_socket.close()
    print(f"[*] Connexion fermée de {addr} (utilisateur: {username}) dans la salle {room}")

def main():
    init_db()  # Initialisation de la base de données
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 9999))  # Écoute sur toutes les interfaces réseau
    server.listen(5)
    print("[*] En attente de connexions...")

    while True:
        client_socket, addr = server.accept()
        threading.Thread(target=handle_initial_connection, args=(client_socket, addr)).start()

if __name__ == "__main__":
    main()
