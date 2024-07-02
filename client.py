import tkinter as tk
from tkinter import messagebox, filedialog
import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os


# Initialize Tkinter application
app = tk.Tk()

# Global variables for input fields and connection
username_entry = None
password_entry = None
email_entry = None
chat_text = None
input_text = None
client_socket = None
session_key = None
current_room = None
server_ip = "192.168.1.5"
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

    # Subtitle
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
    app.geometry("800x600")
    app.configure(bg='#1c1c1c')

    app.grid_rowconfigure(0, weight=1)
    app.grid_rowconfigure(1, weight=20)
    app.grid_rowconfigure(2, weight=1)
    app.grid_columnconfigure(0, weight=1)
    app.grid_columnconfigure(1, weight=4)

    chat_text = tk.Text(app, state=tk.DISABLED, wrap=tk.WORD, bg="#2b2b2b", fg="#ffffff")
    chat_text.grid(row=0, column=0, columnspan=2, sticky="nsew", padx=10, pady=10)

    input_text = tk.Entry(app, bg="#2b2b2b", fg="#ffffff")
    input_text.grid(row=1, column=0, columnspan=2, sticky="ew", padx=10, pady=10)

    button_frame = tk.Frame(app, bg='#1c1c1c')
    button_frame.grid(row=2, column=0, columnspan=2, pady=10)

    send_button = tk.Button(button_frame, text="Send", command=send_message, bg="#ffffff", fg="#000000")
    send_button.pack(side=tk.LEFT, padx=10, pady=10)

    document_button = tk.Button(button_frame, text="Send Document", command=send_document, bg="#ffffff", fg="#000000")
    document_button.pack(side=tk.LEFT, padx=10, pady=10)

    logout_button = tk.Button(button_frame, text="Logout", command=logout, bg="#ffffff", fg="#000000")
    logout_button.pack(side=tk.LEFT, padx=10, pady=10)

    app.bind("<Return>", lambda event: send_message())

    input_text.focus()
    
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


# Fonction pour soumettre le formulaire
def submit():
    username = username_entry.get()
    email = email_entry.get()
    password = password_entry.get()

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_ip, 9999))
        client_socket.send(f"REGISTER {username} {password} {email}".encode('utf-8'))
        response = client_socket.recv(1024).decode('utf-8')
        messagebox.showinfo("Information", response)
        if "successful" in response.lower():
            show_login()  # Redirection vers la page de login après une inscription réussie
    except Exception as e:
        messagebox.showerror("Error", str(e))
    finally:
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
            update_chat(f"You: {message}\n")  # Update local chat with sent message
        except Exception as e:
            messagebox.showerror("Error", str(e))

def send_document():
    file_path = filedialog.askopenfilename()
    if file_path:
        try:
            # Read document data from file
            with open(file_path, "rb") as file:
                document_data = file.read()
                filename = os.path.basename(file_path).encode('utf-8')
                
                # Prepend filename to document data
                encrypted_message = encrypt_message(b"DOCUMENT " + filename + b'\n' + document_data)
                
                # Send encrypted message
                send_data(encrypted_message)
                
                # Update local chat with document info
                update_chat(f"You sent a document: {os.path.basename(file_path)}\n")
        
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
    global chat_text
    download_folder = "downloads"
    if not os.path.exists(download_folder):
        os.makedirs(download_folder)
    
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
            decrypted_message = decrypt_message(encrypted_message)
            if decrypted_message.startswith(b"DOCUMENT "):
                # Handle document reception
                document_data = decrypted_message[len(b"DOCUMENT "):]
                
                # Extract original filename
                original_filename = document_data.decode('utf-8').split('\n')[0]
                
                # Prompt user to confirm download
                confirm_download = messagebox.askyesno("Document Download", f"Do you want to download: {original_filename}?")
                
                if confirm_download:
                    document_path = os.path.join(download_folder, original_filename)
                    with open(document_path, "wb") as doc_file:
                        doc_file.write(document_data)
                    update_chat(f"Received a document: {original_filename}\n")
                else:
                    update_chat(f"Download of {original_filename} canceled by user.\n")
            else:
                # Handle regular message reception
                message_text = decrypted_message.decode('utf-8')
                update_chat(message_text + "\n")

        except Exception as e:
            print(f"Error receiving message: {str(e)}")
            break
        
        print(f"Message chiffré reçu : {encrypted_message.hex()} (taille : {len(encrypted_message)} octets)")  # Débogage
            chat_text.config(state=tk.NORMAL)
            chat_text.insert(tk.END, f"{sender_info}: {decrypted_message}\n")
            chat_text.config(state=tk.DISABLED)
        except Exception as e:
            print(f"Erreur : {str(e)}")
            break

    client_socket.close()
    show_login()

            

def decrypt_message(encrypted_message):
    global session_key
    iv = encrypted_message[:16]  # Extraire les 16 premiers octets comme IV
    print(f"IV extrait pour le déchiffrement : {iv.hex()} (taille : {len(iv)} octets)")  # Débogage
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message[16:]) + decryptor.finalize()
    print(f"Message déchiffré : {decrypted_message.decode('utf-8')}")  # Débogage
    return decrypted_message

    username_label = tk.Label(app, text="Username *", font=("Arial", 12), fg="#ffffff", bg="#1c1c1c")
    username_label.grid(row=1, column=0, sticky="e", pady=5)
    username_entry = tk.Entry(app, bg="#2b2b2b", fg="#ffffff")
    username_entry.grid(row=1, column=1, sticky="w")

    password_label = tk.Label(app, text="Password *", font=("Arial", 12), fg="#ffffff", bg="#1c1c1c")
    password_label.grid(row=2, column=0, sticky="e", pady=5)
    password_entry = tk.Entry(app, show="*", bg="#2b2b2b", fg="#ffffff")
    password_entry.grid(row=2, column=1, sticky="w")

    email_label = tk.Label(app, text="Email *", font=("Arial", 12), fg="#ffffff", bg="#1c1c1c")
    email_label.grid(row=3, column=0, sticky="e", pady=5)
    email_entry = tk.Entry(app, bg="#2b2b2b", fg="#ffffff")
    email_entry.grid(row=3, column=1, sticky="w")

    register_button = tk.Button(app, text="Register", command=register, bg="#ffffff", fg="#000000")
    register_button.grid(row=4, columnspan=2, pady=10)

    login_label = tk.Label(app, text="Already have an account? Login here", font=("Arial", 10), fg="#ffffff", bg="#1c1c1c", cursor="hand2")
    login_label.grid(row=5, columnspan=2)
    login_label.bind("<Button-1>", show_login)

    error_label = tk.Label(app, text="", fg="red", bg="#1c1c1c")
    error_label.grid(row=6, columnspan=2)

    
def update_chat(message):
    global chat_text
    chat_text.config(state=tk.NORMAL)
    chat_text.insert(tk.END, message)
    chat_text.config(state=tk.DISABLED)
    chat_text.see(tk.END)
    
    
def register():
    username = username_entry.get()
    password = password_entry.get()
    email = email_entry.get()

    if not username or not password or not email:
        messagebox.showerror("Error", "All fields are required.")
        return

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_ip, 9999))

        client_socket.send(f"REGISTER {username} {password} {email}".encode('utf-8'))

        response = client_socket.recv(1024).decode('utf-8')
        if response == "Registration successful":
            messagebox.showinfo("Success", "Registration successful! Please login.")
            client_socket.close()
            show_login()
        else:
            messagebox.showerror("Error", "Registration failed. Please try again.")
            client_socket.close()

    except Exception as e:
        messagebox.showerror("Error", f"Connection failed: {str(e)}")

# Start the application with the login screen
show_login()
app.mainloop()
