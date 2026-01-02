import tkinter as tk
from tkinter import messagebox
import sqlite3
import hashlib
import os

conn = sqlite3.connect("users.db")
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    salt BLOB
)
""")
cursor.execute("""
CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    task TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
""")
conn.commit()
conn.close()

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    password_salt = password.encode() + salt
    hashed_password = hashlib.sha256(password_salt).hexdigest()
    return hashed_password, salt

def register_user():
    username = reg_username_entry.get()
    password = reg_password_entry.get()

    if not username or not password:
        messagebox.showerror("Error", "All fields are required")
        return

    hashed_password, salt = hash_password(password)

    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
            (username, hashed_password, salt)
        )
        conn.commit()
        conn.close()
        messagebox.showinfo("Success", "User registered successfully")
        reg_window.destroy()
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "Username already exists")

def login_user():
    username = login_username_entry.get()
    password = login_password_entry.get()

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT password_hash, salt FROM users WHERE username = ?",
        (username,)
    )
    result = cursor.fetchone()
    conn.close()

    if result:
        stored_hash, salt = result
        computed_hash, _ = hash_password(password, salt)
        if computed_hash == stored_hash:
            messagebox.showinfo("Success", f"Welcome, {username}!")
            open_todo_list(username)
        else:
            messagebox.showerror("Error", "Incorrect password")
    else:
        messagebox.showerror("Error", "Username not found")

def open_registration():
    global reg_window, reg_username_entry, reg_password_entry
    reg_window = tk.Toplevel(window)
    reg_window.title("Register")
    reg_window.geometry("300x200")
    reg_window.resizable(False, False)

    tk.Label(reg_window, text="Username").pack()
    reg_username_entry = tk.Entry(reg_window)
    reg_username_entry.pack(pady=5)

    tk.Label(reg_window, text="Password").pack()
    reg_password_entry = tk.Entry(reg_window, show="*")
    reg_password_entry.pack(pady=5)

    tk.Button(reg_window, text="Register", command=register_user).pack(pady=20)

def open_todo_list(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_id = cursor.fetchone()[0]
    conn.close()

    todo_window = tk.Toplevel(window)
    todo_window.title(f"{username}'s To-Do List")
    todo_window.geometry("400x450")
    todo_window.resizable(False, False)

    tk.Label(todo_window, text=f"{username}'s Tasks", font=("Arial", 14, "bold")).pack(pady=10)

    task_entry = tk.Entry(todo_window, width=30, font=("Arial", 12))
    task_entry.pack(pady=5)

    task_listbox = tk.Listbox(todo_window, width=50, height=15, font=("Arial", 12))
    task_listbox.pack(pady=10)

    def load_tasks():
        task_listbox.delete(0, tk.END)
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT id, task FROM tasks WHERE user_id = ? ORDER BY id", (user_id,))
        tasks = cursor.fetchall()
        conn.close()
        for t in tasks:
            task_listbox.insert(tk.END, f"{t[0]}: {t[1]}")

    def add_task():
        task = task_entry.get().strip()
        if task:
            conn = sqlite3.connect("users.db")
            cursor = conn.cursor()
            cursor.execute("INSERT INTO tasks (user_id, task) VALUES (?, ?)", (user_id, task))
            conn.commit()
            conn.close()
            task_entry.delete(0, tk.END)
            load_tasks()

    def delete_task():
        selected = task_listbox.curselection()
        if selected:
            task_id = int(task_listbox.get(selected[0]).split(":")[0])
            confirm = messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this task?")
            if confirm:
                conn = sqlite3.connect("users.db")
                cursor = conn.cursor()
                cursor.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
                conn.commit()
                conn.close()
                load_tasks()

    tk.Button(todo_window, text="Add Task", width=15, command=add_task, bg="#4CAF50", fg="white").pack(pady=5)
    tk.Button(todo_window, text="Delete Task", width=15, command=delete_task, bg="#f44336", fg="white").pack(pady=5)

    load_tasks()


window = tk.Tk()
window.title("Login")
window.geometry("400x350")
window.resizable(False, False)


tk.Label(window, text="My Productivity App", font=("Arial", 18, "bold")).pack(pady=10)

tk.Label(window, text="Username", font=("Arial", 12)).pack(pady=5)
login_username_entry = tk.Entry(window, font=("Arial", 12))
login_username_entry.pack(pady=5)

tk.Label(window, text="Password", font=("Arial", 12)).pack(pady=5)
login_password_entry = tk.Entry(window, show="*", font=("Arial", 12))
login_password_entry.pack(pady=5)

tk.Button(window, text="Login", width=20, bg="#4CAF50", fg="white", command=login_user).pack(pady=10)
tk.Button(window, text="Register", width=20, bg="#2196F3", fg="white", command=open_registration).pack()

window.mainloop()



