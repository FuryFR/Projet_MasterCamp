import socket
import threading
import sqlite3
import logging
from cryptography.fernet import Fernet
import base64

# Initialize logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# Initialize Fernet encryption key
encryption_key = b'vVSGuIfKJ_ckaInT_KYaygWPmNwsgBBzDXQAOcelF0s='
fernet = Fernet(encryption_key)

# SQLite database initialization function
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

# Register a new user in SQLite database
def register_user(username, password, email):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        hashed_password = fernet.encrypt(password.encode('utf-8')).decode('utf-8')
        c.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', (username, hashed_password, email))
        conn.commit()
        return "Registration successful"
    except sqlite3.IntegrityError:
        return "Username already exists"
    except Exception as e:
        logging.error(f"Error registering user: {str(e)}")
        return f"Error registering user: {str(e)}"
    finally:
        conn.close()

# Authenticate a user against SQLite database
def authenticate_user(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()

    if user:
        stored_password = fernet.decrypt(user[2].encode('utf-8')).decode('utf-8')
        if stored_password == password:
            return True
    return False

def handle_initial_connection(client_socket, addr):
    try:
        logging.info(f"Received initial connection from {addr}")

        message = client_socket.recv(1024).decode('utf-8')
        logging.info(f"Received initial message from {addr}: {message}")

        if not message:
            logging.warning("Empty message received")
            client_socket.send("Empty message received".encode('utf-8'))
            return

        # Decrypt the message from client
        try:
            decoded_message = base64.urlsafe_b64decode(message)
            decrypted_message = fernet.decrypt(decoded_message).decode('utf-8')
            logging.info(f"Decrypted message: {decrypted_message}")

            # Log the decrypted message to check its content
            logging.info(f"Decrypted message content: {decrypted_message}")

            # Split the decrypted message into parts
            parts = decrypted_message.split()
            command = parts[0]

            # Validate and process commands
            if command == "LOGIN":
                if len(parts) != 3:
                    raise ValueError("Invalid LOGIN command format")
                _, username, password = parts
                if authenticate_user(username, password):
                    client_socket.send("Login successful".encode('utf-8'))
                    logging.info(f"User {username} logged in successfully")
                    handle_room_selection(client_socket, addr, username)
                else:
                    client_socket.send("Login failed".encode('utf-8'))
                client_socket.close()

            elif command == "REGISTER":
                if len(parts) != 4:
                    raise ValueError("Invalid REGISTER command format")
                _, username, password, email = parts
                response = register_user(username, password, email)
                client_socket.send(response.encode('utf-8'))
                client_socket.close()

            else:
                # Log an indication if the command is unexpected
                logging.warning(f"Unexpected command received: {command}")
                client_socket.send("Invalid command".encode('utf-8'))
                client_socket.close()

        except ValueError as ve:
            logging.error(f"Invalid command format: {str(ve)}")
            client_socket.send(f"Invalid command format: {str(ve)}".encode('utf-8'))
            client_socket.close()

        except Exception as e:
            logging.error(f"Error handling message: {str(e)}")
            client_socket.send(f"Server error: {str(e)}".encode('utf-8'))
            client_socket.close()

    except Exception as e:
        logging.error(f"Error handling connection from {addr}: {str(e)}")
        client_socket.send(f"Server error: {str(e)}".encode('utf-8'))
        client_socket.close()

# Handle room selection or other subsequent actions
def handle_room_selection(client_socket, addr, username):
    # Implement room selection or any other subsequent actions here
    pass

# Main function to start the server
def main():
    init_db()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 9999))
    server.listen(5)
    logging.info("[*] Waiting for connections...")

    while True:
        client_socket, addr = server.accept()
        threading.Thread(target=handle_initial_connection, args=(client_socket, addr)).start()

if __name__ == "__main__":
    main()
