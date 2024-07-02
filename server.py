import socket
import threading
import sqlite3
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

clients = []
clients_lock = threading.Lock()
room_key = os.urandom(32)  # Clé de session symétrique de 256 bits pour AES

# Chemins des fichiers
DB_PATH = '/home/parallels/Projet/users.db'
KEYS_DIR = '/home/parallels/Projet/keys/'

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

def register_user(username, password, email):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', (username, password, email))
        conn.commit()
        # Générer les clés pour l'utilisateur nouvellement inscrit
        generate_keys(username)
        return "Registration successful"
    except sqlite3.IntegrityError:
        return "Username already exists"
    finally:
        conn.close()

def authenticate_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
    user = c.fetchone()
    conn.close()
    return user is not None

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

def send_session_key(client_socket):
    try:
        # Envoyer la clé de session non chiffrée
        client_socket.send(room_key)
    except Exception as e:
        print(f"Erreur lors de l'envoi de la clé de session: {str(e)}")

def handle_initial_connection(client_socket, addr):
    try:
        message = client_socket.recv(1024).decode('utf-8')
        if message.startswith("LOGIN"):
            _, username, password = message.split()
            if authenticate_user(username, password):
                client_socket.send("Login successful".encode('utf-8'))
                with clients_lock:
                    clients.append((client_socket, addr, username))  # Ajouter le nom d'utilisateur à la liste des clients
                threading.Thread(target=handle_client, args=(client_socket, addr, username)).start()
                # Envoyer la clé de session
                send_session_key(client_socket)
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

def handle_client(client_socket, addr, username):
    print(f"[*] Nouvelle connexion de {addr} (utilisateur: {username})")
    while True:
        try:
            # Lire l'en-tête pour obtenir la longueur du message
            header = client_socket.recv(4)
            if not header:
                break
            message_length = int.from_bytes(header, byteorder='big')

            # Lire le message complet
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

            # Relayer uniquement le message chiffré avec l'en-tête correct
            for client in clients:
                if client[0] != client_socket:
                    try:
                        print(f"Envoi du message à {client[2]}")
                        client[0].send(header + encrypted_message)
                    except Exception as e:
                        print(f"Erreur lors de l'envoi du message à {client[2]} : {str(e)}")
                        client[0].close()
                        clients.remove(client)
        except ConnectionResetError:
            break
        except Exception as e:
            print(f"Erreur : {str(e)}")
            break
    with clients_lock:
        clients.remove((client_socket, addr, username))
    client_socket.close()
    print(f"[*] Connexion fermée de {addr} (utilisateur: {username})")


def broadcast_message(message, sender_socket):
    with clients_lock:
        for client_socket, addr, username in clients:
            if client_socket != sender_socket:
                try:
                    print(f"Envoi du message à {username}")
                    print(f"Message relayé : {message.hex()} (taille : {len(message)} octets)")  # Débogage
                    client_socket.send(message)
                except Exception as e:
                    print(f"Erreur lors de l'envoi du message à {username} : {str(e)}")
                    client_socket.close()
                    clients.remove((client_socket, addr, username))


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
