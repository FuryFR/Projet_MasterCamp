import tkinter as tk
from tkinter import messagebox
import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

app = tk.Tk()

username_entry = None
password_entry = None
email_entry = None
chat_text = None
input_text = None
client_socket = None
session_key = None
current_room = None
server_ip = "172.20.10.6"
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

def show_signup():
    global username_entry, email_entry, password_entry
    for widget in app.winfo_children():
        widget.destroy()
    app.title("Registration Form")
    app.geometry("500x400")
    app.configure(bg='#1c1c1c')

    app.grid_rowconfigure(0, weight=1)
    app.grid_rowconfigure(1, weight=1)
    app.grid_rowconfigure(2, weight=1)
    app.grid_rowconfigure(3, weight=1)
    app.grid_rowconfigure(4, weight=1)
    app.grid_rowconfigure(5, weight=1)
    app.grid_rowconfigure(6, weight=1)
    app.grid_columnconfigure(0, weight=1)
    app.grid_columnconfigure(1, weight=1)

    title_label = tk.Label(app, text="Registration form", font=("Arial", 18), fg="#ffffff", bg="#1c1c1c")
    title_label.grid(row=0, columnspan=2, pady=10)

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


def show_room_selection():
    for widget in app.winfo_children():
        widget.destroy()
    app.title("Room Selection")
    app.geometry("500x300")
    app.configure(bg='#1c1c1c')

    app.grid_rowconfigure(0, weight=1)
    app.grid_rowconfigure(1, weight=1)
    app.grid_rowconfigure(2, weight=1)
    app.grid_rowconfigure(3, weight=1)
    app.grid_rowconfigure(4, weight=1)
    app.grid_rowconfigure(5, weight=1)
    app.grid_columnconfigure(0, weight=1)

    title_label = tk.Label(app, text="Select a Room", font=("Arial", 18), fg="#ffffff", bg="#1c1c1c")
    title_label.grid(row=0, columnspan=2, pady=10)

    for i in range(1, 6):
        room_button = tk.Button(app, text=f"Room {i}", command=lambda i=i: join_room(i), bg="#ffffff", fg="#000000")
        room_button.grid(row=i, column=0, pady=10)

def show_chatroom(room):
    global chat_text, input_text, current_room
    current_room = room
    for widget in app.winfo_children():
        widget.destroy()
    app.title(f"Chatroom - Room {room}")
    app.geometry("500x400")

    app.configure(bg='#1c1c1c')

    app.grid_rowconfigure(0, weight=1)
    app.grid_rowconfigure(1, weight=0)
    app.grid_rowconfigure(2, weight=0)
    app.grid_columnconfigure(0, weight=1)

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
    
    send_file_button = tk.Button(input_frame, text="Send File", command=send_file, bg="#ffffff", fg="#000000")
    send_file_button.pack(side=tk.RIGHT, padx=5, pady=5)

    logout_button = tk.Button(app, text="Logout", command=logout, bg="#ffffff", fg="#000000")
    logout_button.grid(row=2, column=0, pady=10)

    threading.Thread(target=receive_messages, daemon=True).start()


from tkinter import filedialog

def send_file():
    file_path = filedialog.askopenfilename()
    if file_path and client_socket:
        try:
            with open(file_path, "rb") as file:
                file_data = file.read()
                file_name = os.path.basename(file_path)
                message = f"FILE {file_name}".encode('utf-8') + b"\x00" + file_data
                message_length = len(message)
                header = message_length.to_bytes(4, byteorder='big')
                client_socket.send(header + message)
                chat_text.config(state=tk.NORMAL)
                chat_text.insert(tk.END, f"You sent a file: {file_name}\n")
                chat_text.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Error", str(e))



def logout():
    global client_socket
    if client_socket:
        try:
            client_socket.send("LOGOUT".encode('utf-8'))
        except Exception as e:
            messagebox.showerror("Error", str(e))
        client_socket.close()
    show_login()

def receive_session_key(client_socket):
    session_key = client_socket.recv(32)
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
            show_login()
    except Exception as e:
        messagebox.showerror("Error", str(e))
    finally:
        client_socket.close()

def encrypt_message(message):
    global session_key
    iv = os.urandom(16)
    print(f"IV généré pour le chiffrement : {iv.hex()} (taille : {len(iv)} octets)")
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = iv + encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    print(f"Message chiffré : {encrypted_message.hex()} (taille : {len(encrypted_message)} octets)")
    return encrypted_message

def send_message(chat_text, input_text):
    message = input_text.get()
    if message and client_socket:
        try:
            encrypted_message = encrypt_message(message)
            message_length = len(encrypted_message)
            header = message_length.to_bytes(4, byteorder='big')
            print(f"Taille du message envoyé : {message_length} octets")
            print(f"Message envoyé : {header.hex()} + {encrypted_message.hex()}")
            client_socket.send(header + encrypted_message)
            chat_text.config(state=tk.NORMAL)
            chat_text.insert(tk.END, f"You: {message}\n")
            chat_text.config(state=tk.DISABLED)
            input_text.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", str(e))

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
                continue
            else:
                print(f"Unexpected response: {response}")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def ask_for_file_permission(sender_info, file_name, file_data):
    def on_accept():
        with open(file_name, "wb") as file:
            file.write(file_data)
        chat_text.config(state=tk.NORMAL)
        chat_text.insert(tk.END, f"You accepted the file: {file_name} from {sender_info}\n")
        chat_text.config(state=tk.DISABLED)
        permission_window.destroy()

    def on_decline():
        chat_text.config(state=tk.NORMAL)
        chat_text.insert(tk.END, f"You declined the file: {file_name} from {sender_info}\n")
        chat_text.config(state=tk.DISABLED)
        permission_window.destroy()

    permission_window = tk.Toplevel(app)
    permission_window.title("File Reception Permission")
    permission_window.geometry("400x200")
    permission_window.configure(bg='#1c1c1c')

    message_label = tk.Label(permission_window, text=f"{sender_info} wants to send you a file: {file_name}\nDo you accept?", bg='#1c1c1c', fg='#ffffff', wraplength=300)
    message_label.pack(pady=20)

    button_frame = tk.Frame(permission_window, bg='#1c1c1c')
    button_frame.pack(pady=20)

    accept_button = tk.Button(button_frame, text="Accept", command=on_accept, bg="#76c7c0", fg="#000000")
    accept_button.pack(side=tk.LEFT, padx=10)

    decline_button = tk.Button(button_frame, text="Decline", command=on_decline, bg="#ff6347", fg="#000000")
    decline_button.pack(side=tk.RIGHT, padx=10)


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
            print(f"Taille du message attendu : {message_length} octets")

            message = client_socket.recv(message_length)
            if not message:
                break

            if message.startswith(b"FILE "):
                file_name_end = message.find(b"\x00", 5)
                file_name = message[5:file_name_end].decode('utf-8')
                file_data = message[file_name_end+1:]
                ask_for_file_permission(sender_info, file_name, file_data)
            else:
                encrypted_message = message
                print(f"Message chiffré reçu : {encrypted_message.hex()} (taille : {len(encrypted_message)} octets)")
                decrypted_message = decrypt_message(encrypted_message).decode('utf-8')
                chat_text.config(state=tk.NORMAL)
                chat_text.insert(tk.END, f"{sender_info}: {decrypted_message}\n")
                chat_text.config(state=tk.DISABLED)
        except Exception as e:
            print(f"Erreur : {str(e)}")
            break



def decrypt_message(encrypted_message):
    global session_key
    iv = encrypted_message[:16]
    print(f"IV extrait pour le déchiffrement : {iv.hex()} (taille : {len(iv)} octets)")
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message[16:]) + decryptor.finalize()
    print(f"Message déchiffré : {decrypted_message.decode('utf-8')}")
    return decrypted_message

show_login()

app.mainloop()
