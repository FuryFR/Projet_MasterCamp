import tkinter as tk
from tkinter import messagebox
import socket
import threading

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

# Fonction pour afficher la fenêtre de connexion
def show_login():
    global username_entry, password_entry
    for widget in app.winfo_children():
        widget.destroy()
    app.title("Login Form")
    app.geometry("500x300")
    app.configure(bg='black')

    # Utiliser grid pour un layout responsive
    app.grid_rowconfigure(0, weight=1)
    app.grid_rowconfigure(1, weight=1)
    app.grid_rowconfigure(2, weight=1)
    app.grid_rowconfigure(3, weight=1)
    app.grid_rowconfigure(4, weight=1)
    app.grid_columnconfigure(0, weight=1)
    app.grid_columnconfigure(1, weight=1)

    # Ajouter le titre
    title_label = tk.Label(app, text="LOGIN", font=("Arial", 18), fg="green", bg="black")
    title_label.grid(row=0, columnspan=2, pady=10)

    subtitle_label = tk.Label(app, text="Discuss your favorite technology with the community!", font=("Arial", 10), fg="green", bg="black")
    subtitle_label.grid(row=1, columnspan=2)

    # Ajouter les champs de saisie
    username_label = tk.Label(app, text="Username *", font=("Arial", 12), fg="green", bg="black")
    username_label.grid(row=2, column=0, sticky="e", pady=5)
    username_entry = tk.Entry(app)
    username_entry.grid(row=2, column=1, sticky="w")

    password_label = tk.Label(app, text="Password *", font=("Arial", 12), fg="green", bg="black")
    password_label.grid(row=3, column=0, sticky="e", pady=5)
    password_entry = tk.Entry(app, show="*")
    password_entry.grid(row=3, column=1, sticky="w")

    # Ajouter les boutons
    connect_button = tk.Button(app, text="Connect", command=connect)
    connect_button.grid(row=4, columnspan=2, pady=10)

    signup_label = tk.Label(app, text="Signup", font=("Arial", 10), fg="green", bg="black", cursor="hand2")
    signup_label.grid(row=5, columnspan=2)

    signup_label.bind("<Button-1>", lambda e: show_signup())

# Fonction pour afficher la fenêtre d'inscription
def show_signup():
    global username_entry, email_entry, password_entry, gender_var, student_id_entry
    for widget in app.winfo_children():
        widget.destroy()
    app.title("Registration Form")
    app.geometry("500x400")
    app.configure(bg='black')

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
    title_label = tk.Label(app, text="Registration form", font=("Arial", 18), fg="green", bg="black")
    title_label.grid(row=0, columnspan=2, pady=10)

    # Ajouter les champs de saisie
    username_label = tk.Label(app, text="Username *", font=("Arial", 12), fg="green", bg="black")
    username_label.grid(row=1, column=0, sticky="e", pady=2)
    username_entry = tk.Entry(app)
    username_entry.grid(row=1, column=1, sticky="w")

    email_label = tk.Label(app, text="Email *", font=("Arial", 12), fg="green", bg="black")
    email_label.grid(row=2, column=0, sticky="e", pady=2)
    email_entry = tk.Entry(app)
    email_entry.grid(row=2, column=1, sticky="w")

    password_label = tk.Label(app, text="Password *", font=("Arial", 12), fg="green", bg="black")
    password_label.grid(row=3, column=0, sticky="e", pady=2)
    password_entry = tk.Entry(app, show="*")
    password_entry.grid(row=3, column=1, sticky="w")

    gender_label = tk.Label(app, text="Gender", font=("Arial", 12), fg="green", bg="black")
    gender_label.grid(row=4, column=0, sticky="e", pady=2)
    gender_var = tk.StringVar(value="Male")
    gender_frame = tk.Frame(app, bg="black")
    gender_frame.grid(row=4, column=1, sticky="w")
    male_rb = tk.Radiobutton(gender_frame, text="Male", variable=gender_var, value="Male", fg="green", bg="black", selectcolor="black")
    male_rb.pack(side=tk.LEFT, padx=5)
    female_rb = tk.Radiobutton(gender_frame, text="Female", variable=gender_var, value="Female", fg="green", bg="black", selectcolor="black")
    female_rb.pack(side=tk.LEFT, padx=5)

    student_id_label = tk.Label(app, text="Student ID *", font=("Arial", 12), fg="green", bg="black")
    student_id_label.grid(row=5, column=0, sticky="e", pady=2)
    student_id_entry = tk.Entry(app)
    student_id_entry.grid(row=5, column=1, sticky="w")

    # Ajouter les boutons
    submit_button = tk.Button(app, text="Submit", command=submit)
    submit_button.grid(row=6, columnspan=2, pady=10)

    login_label = tk.Label(app, text="Login", font=("Arial", 10), fg="green", bg="black", cursor="hand2")
    login_label.grid(row=7, columnspan=2)

    login_label.bind("<Button-1>", lambda e: show_login())

# Fonction pour afficher la fenêtre de chatroom
def show_chatroom():
    global chat_text, input_text
    for widget in app.winfo_children():
        widget.destroy()
    app.title("Chatroom")
    app.geometry("500x400")
    app.configure(bg='black')

    # Utiliser grid pour un layout responsive
    app.grid_rowconfigure(0, weight=1)
    app.grid_rowconfigure(1, weight=1)
    app.grid_rowconfigure(2, weight=1)
    app.grid_rowconfigure(3, weight=0)
    app.grid_columnconfigure(0, weight=1)
    app.grid_columnconfigure(1, weight=0)

    # Frame pour les messages
    chat_frame = tk.Frame(app, bg='black')
    chat_frame.grid(row=0, column=0, columnspan=2, sticky="nsew")

    chat_text = tk.Text(chat_frame, bg='black', fg='green', state=tk.DISABLED)
    chat_text.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)

    user_list = tk.Listbox(app, bg='black', fg='green')
    user_list.grid(row=0, column=1, rowspan=2, sticky="nsew", padx=5, pady=5)
    user_list.insert(tk.END, "guest")

    input_frame = tk.Frame(app, bg='black')
    input_frame.grid(row=1, column=0, sticky="nsew")

    input_text = tk.Entry(input_frame, bg='black', fg='green')
    input_text.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=5, pady=5)

    send_button = tk.Button(input_frame, text="Send", command=lambda: send_message(chat_text, input_text))
    send_button.pack(side=tk.RIGHT, padx=5, pady=5)

    # Démarrer le thread pour recevoir les messages
    threading.Thread(target=receive_messages, daemon=True).start()

# Fonction de connexion
def connect():
    global client_socket
    username = username_entry.get()
    password = password_entry.get()
    # Logique de connexion ici
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_ip = "192.168.1.164"  # Remplacez par l'adresse IP de votre serveur
        client_socket.connect((server_ip, 9999))
        messagebox.showinfo("Information", f"Username: {username}\nPassword: {password}")
        show_chatroom()
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Fonction de soumission du formulaire
def submit():
    username = username_entry.get()
    email = email_entry.get()
    password = password_entry.get()
    gender = gender_var.get()
    student_id = student_id_entry.get()
    # Logique de soumission du formulaire ici
    messagebox.showinfo("Information", f"Username: {username}\nEmail: {email}\nPassword: {password}\nGender: {gender}\nStudent ID: {student_id}")

# Fonction pour envoyer un message
def send_message(chat_text, input_text):
    message = input_text.get()
    if message and client_socket:
        try:
            client_socket.send(message.encode('utf-8'))
            chat_text.config(state=tk.NORMAL)
            chat_text.insert(tk.END, f"You: {message}\n")
            chat_text.config(state=tk.DISABLED)
            input_text.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", str(e))

# Fonction pour recevoir des messages du serveur
def receive_messages():
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if not message:
                break
            chat_text.config(state=tk.NORMAL)
            chat_text.insert(tk.END, f"{message}\n")
            chat_text.config(state=tk.DISABLED)
        except Exception as e:
            break

# Afficher la fenêtre de connexion par défaut
show_login()

app.mainloop()
