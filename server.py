import socket
import threading
import sqlite3

clients = []
clients_lock = threading.Lock()

# Initialiser la base de données
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
            message = client_socket.recv(1024).decode('utf-8')
            if not message:
                break
            if message == "LOGOUT":
                print(f"[*] Déconnexion de {username}")
                break
            print(f"Message de {username} | {addr} : {message}")
            broadcast_message(f"{username}: {message}", client_socket)
        except ConnectionResetError:
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
                    client_socket.send(message.encode('utf-8'))
                except:
                    client_socket.close()
                    clients.remove((client_socket, addr, username))

def main():
    init_db()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 9999))  # Écoute sur toutes les interfaces réseau
    server.listen(5)
    print("[*] En attente de connexions...")

    while True:
        client_socket, addr = server.accept()
        threading.Thread(target=handle_initial_connection, args=(client_socket, addr)).start()

if __name__ == "__main__":
    main()
