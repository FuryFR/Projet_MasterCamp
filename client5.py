import tkinter as tk
from tkinter import messagebox
import socket
import threading
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64

# Fernet encryption key (must be the same as the server's)
encryption_key = b'c7mC_8RkZjUF-P4yHNTurkGGRRHrdxLczhQO0JbGb_s='
fernet = Fernet(encryption_key)

# Load RSA public key for encrypting messages
with open("public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(key_file.read())

# Load RSA private key for decrypting messages
with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(key_file.read(), password=None)

def fernet_encrypt(message):
    encrypted = fernet.encrypt(message.encode())
    return base64.urlsafe_b64encode(encrypted).decode()

def fernet_decrypt(encrypted_message):
    decoded = base64.urlsafe_b64decode(encrypted_message)
    return fernet.decrypt(decoded).decode()

def rsa_encrypt(message):
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.urlsafe_b64encode(encrypted).decode()

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

# Initialize the Tkinter application
app = tk.Tk()

# Global variables for input fields and connection
username_entry = None
password_entry = None
email_entry = None
gender_var = None
student_id_entry = None
chat_text = None
input_text = None
client_socket = None

# Function to show the login window
def show_login():
    global username_entry, password_entry
    for widget in app.winfo_children():
        widget.destroy()
    app.title("Login Form")
    app.geometry("500x300")
    app.configure(bg='#1c1c1c')

    # Use grid for a responsive layout
    app.grid_rowconfigure(0, weight=1)
    app.grid_rowconfigure(1, weight=1)
    app.grid_rowconfigure(2, weight=1)
    app.grid_rowconfigure(3, weight=1)
    app.grid_rowconfigure(4, weight=1)
    app.grid_columnconfigure(0, weight=1)
    app.grid_columnconfigure(1, weight=1)

    # Add title
    title_label = tk.Label(app, text="LOGIN", font=("Arial", 18), fg="#ffffff", bg="#1c1c1c")
    title_label.grid(row=0, columnspan=2, pady=10)

    subtitle_label = tk.Label(app, text="Discuss your favorite technology with the community!", font=("Arial", 10), fg="#c5c5c5", bg="#1c1c1c")
    subtitle_label.grid(row=1, columnspan=2)

    # Add input fields
    username_label = tk.Label(app, text="Username *", font=("Arial", 12), fg="#ffffff", bg="#1c1c1c")
    username_label.grid(row=2, column=0, sticky="e", pady=5)
    username_entry = tk.Entry(app, bg="#2b2b2b", fg="#ffffff")
    username_entry.grid(row=2, column=1, sticky="w")

    password_label = tk.Label(app, text="Password *", font=("Arial", 12), fg="#ffffff", bg="#1c1c1c")
    password_label.grid(row=3, column=0, sticky="e", pady=5)
    password_entry = tk.Entry(app, show="*", bg="#2b2b2b", fg="#ffffff")
    password_entry.grid(row=3, column=1, sticky="w")

    # Add buttons
    connect_button = tk.Button(app, text="Connect", command=connect, bg="#ffffff", fg="#000000")
    connect_button.grid(row=4, columnspan=2, pady=10)

    signup_label = tk.Label(app, text="Signup", font=("Arial", 10), fg="#76c7c0", bg="#1c1c1c", cursor="hand2")
    signup_label.grid(row=5, columnspan=2)
    signup_label.bind("<Button-1>", lambda e: show_signup())

# Function to show the signup window
def show_signup():
    global username_entry, email_entry, password_entry, gender_var, student_id_entry
    for widget in app.winfo_children():
        widget.destroy()
    app.title("Registration Form")
    app.geometry("500x400")
    app.configure(bg='#1c1c1c')

    # Use grid for a responsive layout
    app.grid_rowconfigure(0, weight=1)
    app.grid_rowconfigure(1, weight=1)
    app.grid_rowconfigure(2, weight=1)
    app.grid_rowconfigure(3, weight=1)
    app.grid_rowconfigure(4, weight=1)
    app.grid_rowconfigure(5, weight=1)
    app.grid_rowconfigure(6, weight=1)
    app.grid_columnconfigure(0, weight=1)
    app.grid_columnconfigure(1, weight=1)

    # Add title
    title_label = tk.Label(app, text="Registration form", font=("Arial", 18), fg="#ffffff", bg="#1c1c1c")
    title_label.grid(row=0, columnspan=2, pady=10)

    # Add input fields
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

    gender_label = tk.Label(app, text="Gender", font=("Arial", 12), fg="#ffffff", bg="#1c1c1c")
    gender_label.grid(row=4, column=0, sticky="e", pady=2)
    gender_var = tk.StringVar(value="Male")
    gender_frame = tk.Frame(app, bg="#1c1c1c")
    gender_frame.grid(row=4, column=1, sticky="w")
    male_rb = tk.Radiobutton(gender_frame, text="Male", variable=gender_var, value="Male", fg="#ffffff", bg="#1c1c1c", selectcolor="#1c1c1c")
    male_rb.pack(side=tk.LEFT, padx=5)
    female_rb = tk.Radiobutton(gender_frame, text="Female", variable=gender_var, value="Female", fg="#ffffff", bg="#1c1c1c", selectcolor="#1c1c1c")
    female_rb.pack(side=tk.LEFT, padx=5)

    student_id_label = tk.Label(app, text="Student ID *", font=("Arial", 12), fg="#ffffff", bg="#1c1c1c")
    student_id_label.grid(row=5, column=0, sticky="e", pady=2)
    student_id_entry = tk.Entry(app, bg="#2b2b2b", fg="#ffffff")
    student_id_entry.grid(row=5, column=1, sticky="w")

    # Add buttons
    submit_button = tk.Button(app, text="Submit", command=submit, bg="#ffffff", fg="#000000")
    submit_button.grid(row=6, columnspan=2, pady=10)

    login_label = tk.Label(app, text="Login", font=("Arial", 10), fg="#76c7c0", bg="#1c1c1c", cursor="hand2")
    login_label.grid(row=7, columnspan=2)
    login_label.bind("<Button-1>", lambda e: show_login())

# Function to show the chatroom window
def show_chatroom():
    global chat_text, input_text
    for widget in app.winfo_children():
        widget.destroy()
    app.title("Chatroom")
    app.geometry("800x600")
    app.configure(bg='#1c1c1c')

    # Use grid for a responsive layout
    app.grid_rowconfigure(0, weight=9)
    app.grid_rowconfigure(1, weight=1)
    app.grid_rowconfigure(2, weight=1)
    app.grid_columnconfigure(0, weight=1)

    # Frame for chat display
    chat_frame = tk.Frame(app, bg='#2b2b2b')
    chat_frame.grid(row=0, column=0, sticky="nsew")
    chat_text = tk.Text(chat_frame, state=tk.DISABLED, bg='#2b2b2b', fg='#ffffff')
    chat_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    # Frame for message input
    input_frame = tk.Frame(app, bg='#1c1c1c')
    input_frame.grid(row=1, column=0, sticky="ew")

    input_text = tk.Entry(input_frame, bg='#2b2b2b', fg='#ffffff')
    input_text.pack(fill=tk.X, padx=5, pady=5, side=tk.LEFT, expand=True)
    send_button = tk.Button(input_frame, text="Send", command=send_message, bg="#ffffff", fg="#000000")
    send_button.pack(padx=5, pady=5, side=tk.RIGHT)

    # Frame for room control
    control_frame = tk.Frame(app, bg='#1c1c1c')
    control_frame.grid(row=2, column=0, sticky="ew")

    join_button = tk.Button(control_frame, text="Join Room", command=join_room, bg="#ffffff", fg="#000000")
    join_button.pack(side=tk.LEFT, padx=5, pady=5)
    leave_button = tk.Button(control_frame, text="Leave Room", command=leave_room, bg="#ffffff", fg="#000000")
    leave_button.pack(side=tk.LEFT, padx=5, pady=5)
    logout_button = tk.Button(control_frame, text="Logout", command=logout, bg="#ffffff", fg="#000000")
    logout_button.pack(side=tk.RIGHT, padx=5, pady=5)

def connect():
    global client_socket
    username = username_entry.get()
    password = password_entry.get()

    if not username or not password:
        messagebox.showerror("Error", "Please enter both username and password")
        return

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', 12345))
        encrypted_message = fernet_encrypt(f'login,{username},{password}')
        client_socket.sendall(encrypted_message.encode())

        response = fernet_decrypt(client_socket.recv(1024).decode())
        if response == 'success':
            show_chatroom()
            threading.Thread(target=receive_messages).start()
        else:
            messagebox.showerror("Error", "Login failed")

    except Exception as e:
        messagebox.showerror("Error", str(e))

def submit():
    username = username_entry.get()
    email = email_entry.get()
    password = password_entry.get()
    gender = gender_var.get()
    student_id = student_id_entry.get()

    if not username or not email or not password or not student_id:
        messagebox.showerror("Error", "Please fill all required fields")
        return

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', 12345))
        encrypted_message = fernet_encrypt(f'register,{username},{email},{password},{gender},{student_id}')
        client_socket.sendall(encrypted_message.encode())

        response = fernet_decrypt(client_socket.recv(1024).decode())
        if response == 'success':
            show_login()
        else:
            messagebox.showerror("Error", "Registration failed")

    except Exception as e:
        messagebox.showerror("Error", str(e))

def join_room():
    if client_socket:
        encrypted_message = fernet_encrypt('join')
        client_socket.sendall(encrypted_message.encode())

def leave_room():
    if client_socket:
        encrypted_message = fernet_encrypt('leave')
        client_socket.sendall(encrypted_message.encode())

def logout():
    if client_socket:
        encrypted_message = fernet_encrypt('logout')
        client_socket.sendall(encrypted_message.encode())
        client_socket.close()
    show_login()

def send_message():
    message = input_text.get()
    if message and client_socket:
        encrypted_message = rsa_encrypt(message)
        client_socket.sendall(encrypted_message.encode())
        input_text.delete(0, tk.END)

def receive_messages():
    while True:
        try:
            encrypted_message = client_socket.recv(1024).decode()
            message = rsa_decrypt(encrypted_message)
            chat_text.configure(state=tk.NORMAL)
            chat_text.insert(tk.END, message + '\n')
            chat_text.configure(state=tk.DISABLED)
        except Exception as e:
            break

show_login()
app.mainloop()
