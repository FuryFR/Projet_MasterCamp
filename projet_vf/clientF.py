import tkinter as tk
from tkinter import messagebox
import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from cryptography.fernet import Fernet,InvalidToken
import base64

encryption_key = b'o56gSWzn6V0oizS0DLHS3u6Tm58EUxylatAJjIvmpwM='
fernet = Fernet(encryption_key)

def fernet_encrypt(message):
    encrypted = fernet.encrypt(message.encode())
    return base64.urlsafe_b64encode(encrypted).decode()

def fernet_decrypt(encrypted_message):
    # Ensure the base64 string is properly padded
    padded_message = encrypted_message + b'=' * (4 - len(encrypted_message) % 4)
    decoded = base64.urlsafe_b64decode(padded_message)
    return fernet.decrypt(decoded).decode()


# Initialiser l'application Tkinter
app = tk.Tk()

# Variables globales pour les champs d'entrée et la connexion
username_entry = None
password_entry = None
email_entry = None
chat_text = None
input_text = None
client_socket = None
session_key = None
current_room = None
server_ip = "192.168.0.21"
otp_entry = None

def show_login():
    global username_entry, password_entry, otp_entry
    for widget in app.winfo_children():
        widget.destroy()
    app.title("Login Form")
    app.geometry("500x300")
    app.configure(bg='#1c1c1c')

    app.grid_rowconfigure(0, weight=1)
    app.grid_rowconfigure(1, weight=1)
    app.grid_rowconfigure(2, weight=1)
    app.grid_rowconfigure(3, weight=1)
    app.grid_rowconfigure(4, weight=1)
    app.grid_rowconfigure(5, weight=1)
    app.grid_columnconfigure(0, weight=1)
    app.grid_columnconfigure(1, weight=1)

    title_label = tk.Label(app, text="LOGIN", font=("Arial", 18), fg="#ffffff", bg="#1c1c1c")
    title_label.grid(row=0, columnspan=2, pady=10)

    subtitle_label = tk.Label(app, text="Discuss your favorite technology with the community!", font=("Arial", 10), fg="#c5c5c5", bg="#1c1c1c")
    subtitle_label.grid(row=1, columnspan=2)

    username_label = tk.Label(app, text="Username *", font=("Arial", 12), fg="#ffffff", bg="#1c1c1c")
    username_label.grid(row=2, column=0, sticky="e", pady=5)
    username_entry = tk.Entry(app, bg="#2b2b2b", fg="#ffffff")
    username_entry.grid(row=2, column=1, sticky="w")

    password_label = tk.Label(app, text="Password *", font=("Arial", 12), fg="#ffffff", bg="#1c1c1c")
    password_label.grid(row=3, column=0, sticky="e", pady=5)
    password_entry = tk.Entry(app, show="*", bg="#2b2b2b", fg="#ffffff")
    password_entry.grid(row=3, column=1, sticky="w")

    connect_button = tk.Button(app, text="Connect", command=connect, bg="#ffffff", fg="#000000")
    connect_button.grid(row=5, columnspan=2, pady=10)

    signup_label = tk.Label(app, text="Signup", font=("Arial", 10), fg="#76c7c0", bg="#1c1c1c", cursor="hand2")
    signup_label.grid(row=6, columnspan=2)
    signup_label.bind("<Button-1>", lambda e: show_signup())

# Fonction pour afficher la fenêtre d'inscription
def show_signup():
    global username_entry, email_entry, password_entry
    for widget in app.winfo_children():
        widget.destroy()
    app.title("Registration Form")
    app.geometry("500x400")
    app.configure(bg='#1c1c1c')

    # Utiliser grid pour un layout responsive
    app.grid_rowconfigure(0, weight=1)
    app.grid_rowconfigure(1, weight=1)
    app.grid_rowconfigure(2, weight=1)
    app.grid_rowconfigure(3, weight=1)
    app.grid_rowconfigure(4, weight=1)
    app.grid_rowconfigure(5, weight=1)
    app.grid_rowconfigure(6, weight=1)
    app.grid_columnconfigure(0, weight=1)
    app.grid_columnconfigure(1, weight=1)

    # Ajouter le titre
    title_label = tk.Label(app, text="Registration form", font=("Arial", 18), fg="#ffffff", bg="#1c1c1c")
    title_label.grid(row=0, columnspan=2, pady=10)

    # Ajouter les champs de saisie
    username_label = tk.Label(app, text="Username *", font=("Arial", 12), fg="#ffffff", bg="#1c1c1c")
    username_label.grid(row=1, column=0, sticky="e", pady=2)
    username_entry = tk.Entry(app, bg="#2b2b2b", fg="#ffffff")
    username_entry.grid(row=1, column=1, sticky="w")

    email_label = tk.Label(app, text="Email *", font=("Arial", 12), fg="#ffffff", bg="#1c1c1c")
    email_label.grid(row=2, column=0, sticky="e", pady=2)
    email_entry = tk.Entry(app, bg="#2b2b2b", fg="#ffffff")
    email_entry.grid(row=2, column=1, sticky="w")

    password_label = tk.Label(app, text="Password *", font=("Arial", 12), fg="#ffffff", bg="#1c1c1c")
    password_label.grid(row=3, column=0, sticky="e", pady=2)
    password_entry = tk.Entry(app, show="*", bg="#2b2b2b", fg="#ffffff")
    password_entry.grid(row=3, column=1, sticky="w")

    # Ajouter les boutons
    submit_button = tk.Button(app, text="Submit", command=submit, bg="#ffffff", fg="#000000")
    submit_button.grid(row=6, columnspan=2, pady=10)

    login_label = tk.Label(app, text="Login", font=("Arial", 10), fg="#76c7c0", bg="#1c1c1c", cursor="hand2")
    login_label.grid(row=7, columnspan=2)
    login_label.bind("<Button-1>", lambda e: show_login())


def show_otp_verification():
    global otp_entry
    for widget in app.winfo_children():
        widget.destroy()
    app.title("OTP Verification")
    app.geometry("500x300")
    app.configure(bg='#1c1c1c')

    app.grid_rowconfigure(0, weight=1)
    app.grid_rowconfigure(1, weight=1)
    app.grid_rowconfigure(2, weight=1)
    app.grid_rowconfigure(3, weight=1)
    app.grid_rowconfigure(4, weight=1)
    app.grid_columnconfigure(0, weight=1)
    app.grid_columnconfigure(1, weight=1)

    title_label = tk.Label(app, text="OTP Verification", font=("Arial", 18), fg="#ffffff", bg="#1c1c1c")
    title_label.grid(row=0, columnspan=2, pady=10)

    otp_label = tk.Label(app, text="Enter OTP *", font=("Arial", 12), fg="#ffffff", bg="#1c1c1c")
    otp_label.grid(row=1, column=0, sticky="e", pady=5)
    otp_entry = tk.Entry(app, bg="#2b2b2b", fg="#ffffff")
    otp_entry.grid(row=1, column=1, sticky="w")

    verify_button = tk.Button(app, text="Verify", command=verify_otp, bg="#ffffff", fg="#000000")
    verify_button.grid(row=2, columnspan=2, pady=10)


# Fonction pour afficher la fenêtre de choix de salle
def show_room_selection():
    for widget in app.winfo_children():
        widget.destroy()
    app.title("Room Selection")
    app.geometry("500x300")
    app.configure(bg='#1c1c1c')

    # Utiliser grid pour un layout responsive
    app.grid_rowconfigure(0, weight=1)
    app.grid_rowconfigure(1, weight=1)
    app.grid_rowconfigure(2, weight=1)
    app.grid_rowconfigure(3, weight=1)
    app.grid_rowconfigure(4, weight=1)
    app.grid_rowconfigure(5, weight=1)
    app.grid_columnconfigure(0, weight=1)

    # Ajouter le titre
    title_label = tk.Label(app, text="Select a Room", font=("Arial", 18), fg="#ffffff", bg="#1c1c1c")
    title_label.grid(row=0, columnspan=2, pady=10)

    # Ajouter les boutons pour chaque salle
    for i in range(1, 6):
        room_button = tk.Button(app, text=f"Room {i}", command=lambda i=i: join_room(i), bg="#ffffff", fg="#000000")
        room_button.grid(row=i, column=0, pady=10)

# Fonction pour afficher la fenêtre de chatroom
def show_chatroom(room):
    global chat_text, input_text, current_room
    current_room = room
    for widget in app.winfo_children():
        widget.destroy()
    app.title(f"Chatroom - Room {room}")
    app.geometry("500x400")

    app.configure(bg='#1c1c1c')

    # Utiliser grid pour un layout responsive
    app.grid_rowconfigure(0, weight=1)
    app.grid_rowconfigure(1, weight=0)
    app.grid_rowconfigure(2, weight=0)
    app.grid_columnconfigure(0, weight=1)

    # Frame pour les messages
    chat_frame = tk.Frame(app, bg='#1c1c1c')
    chat_frame.grid(row=0, column=0, sticky="nsew")

    chat_text = tk.Text(chat_frame, bg='#2b2b2b', fg='#ffffff', state=tk.DISABLED)
    chat_text.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)

    input_frame = tk.Frame(app, bg='#1c1c1c')
    input_frame.grid(row=1, column=0, sticky="nsew")

    input_text = tk.Entry(input_frame, bg='#2b2b2b', fg='#ffffff')
    input_text.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=5, pady=5)
    input_text.bind("<Return>", lambda event: send_message(chat_text, input_text))

    send_button = tk.Button(input_frame, text="Send", command=lambda: send_message(chat_text, input_text), bg="#ffffff", fg="#000000")
    send_button.pack(side=tk.RIGHT, padx=5, pady=5)

    logout_button = tk.Button(app, text="Logout", command=logout, bg="#ffffff", fg="#000000")
    logout_button.grid(row=2, column=0, pady=10)

    # Démarrer le thread pour recevoir les messages
    threading.Thread(target=receive_messages, daemon=True).start()

# Fonction de déconnexion
def logout():
    global client_socket
    if client_socket:
        try:
            client_socket.send("LOGOUT".encode('utf-8'))
        except Exception as e:
            messagebox.showerror("Error", str(e))
        client_socket.close()
    show_login()

# Fonction pour recevoir la clé de session
def receive_session_key(client_socket):
    session_key = client_socket.recv(32)  # Recevoir la clé de session de 32 octets
    print(f"Taille de la clé de session reçue : {len(session_key)} octets")
    print(f"Contenu de la clé de session reçue : {session_key.hex()}")
    return session_key

def connect():
    global client_socket, session_key
    username = username_entry.get()
    password = password_entry.get()

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_ip, 9999))
        client_socket.send(f"LOGIN {username} {password}".encode('utf-8'))
        
        while True:
            response = client_socket.recv(1024).decode('utf-8')
            print(f"Server response: {response}")
            if response == "OTP required":
                messagebox.showinfo("Information", "OTP has been sent to your email.")
                show_otp_verification()
                break
            elif response == "Login failed":
                messagebox.showerror("Error", response)
                client_socket.close()
                break
            else:
                print(f"Unexpected response: {response}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def verify_otp():
    global client_socket
    otp = otp_entry.get()

    try:
        client_socket.send(f"OTP {otp}".encode('utf-8'))
        response = client_socket.recv(1024).decode('utf-8')
        print(f"OTP verification response: {response}")
        if response == "Login successful":
            messagebox.showinfo("Information", response)
            show_room_selection()
        elif response == "OTP verification failed":
            messagebox.showerror("Error", response)
            client_socket.close()
        else:
            print(f"Unexpected response: {response}")
    except Exception as e:
        messagebox.showerror("Error", str(e))


from cryptography.fernet import InvalidToken

def submit():
    username = username_entry.get()
    email = email_entry.get()
    password = password_entry.get()

    try:
        # Encrypt the registration details using Fernet
        message = f"REGISTER {username} {password} {email}"
        encrypted_message = fernet.encrypt(message.encode())

        # Connect to the server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_ip, 9999))

        # Send the encrypted message
        client_socket.send(encrypted_message)

        # Receive encrypted server response
        encrypted_response = client_socket.recv(1024)
        
        try:
            # Decrypt the server response using fernet_decrypt
            response = fernet_decrypt(encrypted_response)
        except InvalidToken:
            messagebox.showerror("Error", "Invalid Fernet token received from server")
            client_socket.close()
            return
        except Exception as e:
            messagebox.showerror("Error", f"Error decrypting server response: {str(e)}")
            client_socket.close()
            return

        # Display response message to the user
        messagebox.showinfo("Information", response)

        # Check if registration was successful
        if "successful" in response.lower():
            show_login()  # Redirect to login page after successful registration

    except socket.error as e:
        messagebox.showerror("Error", f"Socket error: {str(e)}")
    except Exception as e:
        messagebox.showerror("Error", f"Unexpected error: {str(e)}")

    finally:
        if client_socket:
            client_socket.close()


# Fonction pour envoyer un message
def encrypt_message(message):
    global session_key
    iv = os.urandom(16)  # Générer un IV de 16 octets
    print(f"IV généré pour le chiffrement : {iv.hex()} (taille : {len(iv)} octets)")  # Débogage
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = iv + encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    print(f"Message chiffré : {encrypted_message.hex()} (taille : {len(encrypted_message)} octets)")  # Débogage
    return encrypted_message

def send_message(chat_text, input_text):
    message = input_text.get()
    if message and client_socket:
        try:
            encrypted_message = encrypt_message(message)
            message_length = len(encrypted_message)
            header = message_length.to_bytes(4, byteorder='big')
            print(f"Taille du message envoyé : {message_length} octets")  # Débogage
            print(f"Message envoyé : {header.hex()} + {encrypted_message.hex()}")  # Débogage
            client_socket.send(header + encrypted_message)
            chat_text.config(state=tk.NORMAL)
            chat_text.insert(tk.END, f"You: {message}\n")
            chat_text.config(state=tk.DISABLED)
            input_text.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", str(e))

# Fonction pour rejoindre une salle
def join_room(room):
    global client_socket, session_key
    try:
        client_socket.send(f"ROOM {room}".encode('utf-8'))
        
        while True:
            response = client_socket.recv(1024).decode('utf-8')
            print(f"Server response: {response}")
            if response == f"Joined room {room}":
                session_key = receive_session_key(client_socket)
                show_chatroom(room)
                break
            elif "Invalid room selection" in response or "Error" in response:
                messagebox.showerror("Error", response)
                break
            elif response.startswith("Select room"):
                continue  # Ignorer les messages de sélection de room supplémentaires
            else:
                print(f"Unexpected response: {response}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Fonction pour recevoir des messages du serveur
def receive_messages():
    while True:
        try:
            sender_info_header = client_socket.recv(4)
            if not sender_info_header:
                break
            sender_info_length = int.from_bytes(sender_info_header, byteorder='big')
            sender_info = client_socket.recv(sender_info_length).decode('utf-8')

            header = client_socket.recv(4)
            if not header:
                break
            message_length = int.from_bytes(header, byteorder='big')
            print(f"Taille du message attendu : {message_length} octets")  # Débogage

            encrypted_message = b""
            while len(encrypted_message) < message_length:
                part = client_socket.recv(message_length - len(encrypted_message))
                if not part:
                    break
                encrypted_message += part

            if not encrypted_message:
                break

            print(f"Message chiffré reçu : {encrypted_message.hex()} (taille : {len(encrypted_message)} octets)")  # Débogage
            message = decrypt_message(encrypted_message).decode('utf-8')
            chat_text.config(state=tk.NORMAL)
            chat_text.insert(tk.END, f"{sender_info}: {message}\n")
            chat_text.config(state=tk.DISABLED)
        except Exception as e:
            print(f"Erreur : {str(e)}")
            break

def decrypt_message(encrypted_message):
    global session_key
    iv = encrypted_message[:16]  # Extraire les 16 premiers octets comme IV
    print(f"IV extrait pour le déchiffrement : {iv.hex()} (taille : {len(iv)} octets)")  # Débogage
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message[16:]) + decryptor.finalize()
    print(f"Message déchiffré : {decrypted_message.decode('utf-8')}")  # Débogage
    return decrypted_message

# Afficher la fenêtre de connexion par défaut
show_login()

app.mainloop()