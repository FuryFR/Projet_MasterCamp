import tkinter as tk
from tkinter import messagebox, filedialog
import socket
import threading
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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
server_ip = "192.168.1.164"

# Function to display login window
def show_login():
    global username_entry, password_entry
    for widget in app.winfo_children():
        widget.destroy()
    app.title("Login Form")
    app.geometry("500x300")
    app.configure(bg='#1c1c1c')

    # Grid layout for responsiveness
    app.grid_rowconfigure(0, weight=1)
    app.grid_rowconfigure(1, weight=1)
    app.grid_rowconfigure(2, weight=1)
    app.grid_rowconfigure(3, weight=1)
    app.grid_rowconfigure(4, weight=1)
    app.grid_columnconfigure(0, weight=1)
    app.grid_columnconfigure(1, weight=1)

    # Title
    title_label = tk.Label(app, text="LOGIN", font=("Arial", 18), fg="#ffffff", bg="#1c1c1c")
    title_label.grid(row=0, columnspan=2, pady=10)

    # Subtitle
    subtitle_label = tk.Label(app, text="Discuss your favorite technology with the community!", font=("Arial", 10), fg="#c5c5c5", bg="#1c1c1c")
    subtitle_label.grid(row=1, columnspan=2)

    # Input fields
    username_label = tk.Label(app, text="Username *", font=("Arial", 12), fg="#ffffff", bg="#1c1c1c")
    username_label.grid(row=2, column=0, sticky="e", pady=5)
    username_entry = tk.Entry(app, bg="#2b2b2b", fg="#ffffff")
    username_entry.grid(row=2, column=1, sticky="w")

    password_label = tk.Label(app, text="Password *", font=("Arial", 12), fg="#ffffff", bg="#1c1c1c")
    password_label.grid(row=3, column=0, sticky="e", pady=5)
    password_entry = tk.Entry(app, show="*", bg="#2b2b2b", fg="#ffffff")
    password_entry.grid(row=3, column=1, sticky="w")

    # Buttons
    connect_button = tk.Button(app, text="Connect", command=connect, bg="#ffffff", fg="#000000")
    connect_button.grid(row=4, columnspan=2, pady=10)

    # Register link
    register_label = tk.Label(app, text="Don't have an account? Register here", font=("Arial", 10), fg="#ffffff", bg="#1c1c1c", cursor="hand2")
    register_label.grid(row=5, columnspan=2)
    register_label.bind("<Button-1>", show_registration)

    # Error message
    error_label = tk.Label(app, text="", fg="red", bg="#1c1c1c")
    error_label.grid(row=6, columnspan=2)

def connect():
    global client_socket, session_key
    username = username_entry.get()
    password = password_entry.get()

    if not username or not password:
        messagebox.showerror("Error", "Username and Password are required.")
        return

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_ip, 9999))

        # Send login command
        client_socket.send(f"LOGIN {username} {password}".encode('utf-8'))

        # Receive response
        response = client_socket.recv(1024).decode('utf-8')
        if response == "Login successful":
            messagebox.showinfo("Success", "Login successful!")
            session_key = client_socket.recv(32)
            print("Received session key:", session_key.hex())
            show_chat()
            threading.Thread(target=receive_messages).start()
        else:
            messagebox.showerror("Error", "Login failed. Please check your credentials.")
            client_socket.close()
            client_socket = None

    except Exception as e:
        messagebox.showerror("Error", f"Connection failed: {str(e)}")
        client_socket = None

def show_chat():
    global chat_text, input_text
    for widget in app.winfo_children():
        widget.destroy()
    app.title("Chat Room")
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
        client_socket.close()
    show_login()

def send_message(event=None):
    message = input_text.get()
    if message and client_socket:
        try:
            encrypted_message = encrypt_message(message.encode('utf-8'))
            send_data(encrypted_message)
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

def send_data(data):
    try:
        message_length = len(data)
        header = message_length.to_bytes(4, byteorder='big')
        client_socket.send(header + data)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def receive_messages():
    global chat_text
    download_folder = "downloads"
    if not os.path.exists(download_folder):
        os.makedirs(download_folder)
    
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

    client_socket.close()
    show_login()

def update_chat(message):
    global chat_text
    chat_text.config(state=tk.NORMAL)
    chat_text.insert(tk.END, message)
    chat_text.config(state=tk.DISABLED)
    chat_text.see(tk.END)

def encrypt_message(message):
    if not session_key:
        raise Exception("No session key available")
    backend = default_backend()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message) + encryptor.finalize()
    return iv + encrypted_message

def decrypt_message(encrypted_message):
    if not session_key:
        raise Exception("No session key available")
    iv = encrypted_message[:16]
    encrypted_message = encrypted_message[16:]
    backend = default_backend()
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    return decrypted_message

def show_registration(event=None):
    global username_entry, password_entry, email_entry
    for widget in app.winfo_children():
        widget.destroy()
    app.title("Registration Form")
    app.geometry("500x350")
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

    title_label = tk.Label(app, text="REGISTER", font=("Arial", 18), fg="#ffffff", bg="#1c1c1c")
    title_label.grid(row=0, columnspan=2, pady=10)

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
