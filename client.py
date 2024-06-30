import tkinter as tk
from tkinter import messagebox
import socket
import threading
from cryptography.fernet import Fernet
import base64

# Use the same encryption key as on the server side
encryption_key = b'vVSGuIfKJ_ckaInT_KYaygWPmNwsgBBzDXQAOcelF0s='
fernet = Fernet(encryption_key)


def encrypt_message(message):
    encrypted = fernet.encrypt(message.encode())
    encoded = base64.urlsafe_b64encode(encrypted)
    return encoded

def decrypt_message(encrypted_message):
    decoded = base64.urlsafe_b64decode(encrypted_message)
    decrypted = fernet.decrypt(decoded).decode()
    return decrypted


# Initialiser l'application Tkinter
app = tk.Tk()

# Variables globales pour les champs d'entrée et la connexion
username_entry = None
password_entry = None
email_entry = None
gender_var = None
student_id_entry = None
chat_text = None
input_text = None
client_socket = None


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

    # Add the title
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

    # Add the title
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

def show_room_selection():
    for widget in app.winfo_children():
        widget.destroy()
    app.title("Room Selection")
    app.geometry("500x300")
    app.configure(bg='#1c1c1c')

    # Use grid for a responsive layout
    app.grid_rowconfigure(0, weight=1)
    app.grid_rowconfigure(1, weight=1)
    app.grid_rowconfigure(2, weight=1)
    app.grid_rowconfigure(3, weight=1)
    app.grid_rowconfigure(4, weight=1)
    app.grid_rowconfigure(5, weight=1)
    app.grid_columnconfigure(0, weight=1)

    # Add the title
    title_label = tk.Label(app, text="Select a Room", font=("Arial", 18), fg="#ffffff", bg="#1c1c1c")
    title_label.grid(row=0, columnspan=2, pady=10)

    # Add buttons for each room
    for i in range(1, 6):
        room_button = tk.Button(app, text=f"Room {i}", command=lambda i=i: join_room(f"{i}"), bg="#ffffff", fg="#000000")
        room_button.grid(row=i, columnspan=2, pady=5)

def show_chatroom(room):
    global chat_text, input_text
    for widget in app.winfo_children():
        widget.destroy()
    app.title(f"Chatroom - Room {room}")
    app.geometry("500x400")
    app.configure(bg='#1c1c1c')

    # Use grid for a responsive layout
    app.grid_rowconfigure(0, weight=1)
    app.grid_rowconfigure(1, weight=1)
    app.grid_rowconfigure(2, weight=1)
    app.grid_rowconfigure(3, weight=1)
    app.grid_rowconfigure(4, weight=1)
    app.grid_columnconfigure(0, weight=1)
    app.grid_columnconfigure(1, weight=1)

    # Add the title
    title_label = tk.Label(app, text=f"Chatroom - Room {room}", font=("Arial", 18), fg="#ffffff", bg="#1c1c1c")
    title_label.grid(row=0, columnspan=2, pady=10)

    # Add chat display
    chat_text = tk.Text(app, wrap=tk.WORD, state=tk.DISABLED, bg="#2b2b2b", fg="#ffffff")
    chat_text.grid(row=1, columnspan=2, padx=10, pady=5, sticky="nsew")

    # Add scrollbar for chat display
    scroll_bar = tk.Scrollbar(app, command=chat_text.yview)
    scroll_bar.grid(row=1, column=2, sticky='nsew')
    chat_text['yscrollcommand'] = scroll_bar.set

    # Add input field for messages
    input_text = tk.Entry(app, bg="#2b2b2b", fg="#ffffff")
    input_text.grid(row=2, columnspan=2, padx=10, pady=10, sticky="ew")

    # Bind Enter key to send message
    input_text.bind("<Return>", lambda event: send_message(room))

    # Add buttons
    send_button = tk.Button(app, text="Send", command=lambda: send_message(room), bg="#ffffff", fg="#000000")
    send_button.grid(row=3, columnspan=2, pady=10)

    leave_button = tk.Button(app, text="Leave Room", command=leave_room, bg="#ffffff", fg="#000000")
    leave_button.grid(row=4, columnspan=2, pady=10)

def connect(username=None, password=None, email=None):
    global client_socket

    try:
        if not client_socket:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect(('192.168.0.21', 9999))
            threading.Thread(target=receive_messages).start()

        if username and password:
            # Perform login
            encrypted_message = encrypt_message(f"LOGIN {username} {password}")
            client_socket.send(encrypted_message)
            response = decrypt_message(client_socket.recv(1024))
            if "successful" in response.lower():
                show_room_selection()
            else:
                messagebox.showerror("Login Failed", response)
        elif username and password and email:
            # Perform registration
            encrypted_message = encrypt_message(f"REGISTER {username} {password} {email}")
            client_socket.send(encrypted_message)
            response = decrypt_message(client_socket.recv(1024))
            messagebox.showinfo("Registration", response)
            if "successful" in response.lower():
                show_login()
        else:
            show_room_selection()

    except ConnectionRefusedError:
        messagebox.showerror("Connection Error", "Connection refused. Make sure the server is running.")
    except Exception as e:
        messagebox.showerror("Connection Error", f"Failed to connect to server: {e}")
        client_socket = None  # Reset client_socket to None on connection failure



def submit():
    global client_socket
    username = username_entry.get()
    email = email_entry.get()
    password = password_entry.get()
    student_ID = student_id_entry.get()

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('192.168.0.21', 9999))  # Try with localhost or 127.0.0.1
        client_socket.send(encrypt_message(f"REGISTER {username} {password} {email} "))

        response = decrypt_message(client_socket.recv(1024))
        messagebox.showinfo("Information", response)
        if "successful" in response.lower():
            show_login()  # Redirect to login page after successful registration
    except socket.timeout:
        messagebox.showerror("Error", "Connection timed out. Check server availability.")
    except ConnectionRefusedError:
        messagebox.showerror("Error", "Connection refused. Make sure the server is running.")
    except Exception as e:
        messagebox.showerror("Error", f"Registration failed: {e}")
    finally:
        if client_socket:
            client_socket.close()



def join_room(room):
    global client_socket
    try:
        encrypted_message = encrypt_message(f"JOIN {room}")
        client_socket.send(encrypted_message)
        response = client_socket.recv(1024)
        decrypted_response = decrypt_message(response)
        if decrypted_response == f"JOINED {room}":
            show_chatroom(room)
        else:
            messagebox.showerror("Room Join Error", f"Failed to join room {room}: {decrypted_response}")
    except Exception as e:
        messagebox.showerror("Room Join Error", f"Failed to join room {room}: {e}")

def leave_room():
    global client_socket
    try:
        encrypted_message = encrypt_message("LEAVE")
        client_socket.send(encrypted_message)
        response = client_socket.recv(1024)
        decrypted_response = decrypt_message(response)
        if decrypted_response == "LEFT":
            show_room_selection()
        else:
            messagebox.showerror("Leave Room Error", f"Failed to leave room: {decrypted_response}")
    except Exception as e:
        messagebox.showerror("Leave Room Error", f"Failed to leave room: {e}")

def send_message(room):
    global input_text, chat_text
    message = input_text.get().strip()
    if message:
        try:
            encrypted_message = encrypt_message(f"MESSAGE {room} {message}")
            client_socket.send(encrypted_message)
            input_text.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Message Send Error", f"Failed to send message: {e}")

def receive_messages():
    global client_socket, chat_text
    try:
        while True:
            response = client_socket.recv(1024)
            decrypted_response = decrypt_message(response)
            if decrypted_response.startswith("MESSAGE"):
                _, room, message = decrypted_response.split(maxsplit=2)
                chat_text.config(state=tk.NORMAL)
                chat_text.insert(tk.END, f"Room {room}: {message}\n")
                chat_text.config(state=tk.DISABLED)
                chat_text.see(tk.END)
            else:
                messagebox.showwarning("Unknown Message", f"Received unknown message: {decrypted_response}")
    except Exception as e:
        messagebox.showerror("Receive Error", f"Error receiving message: {e}")

# Start the application by showing the login form
show_login()

# Run the Tkinter main loop
app.mainloop()
