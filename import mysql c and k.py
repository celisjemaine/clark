import customtkinter as ctk
import tkinter as tk
from tkinter import END, messagebox
import sqlite3
import hashlib

user_text = 'Enter Username'
password_text = 'Enter Password'
signup_user_text = 'User'
signup_password_text = 'Password'

conn = sqlite3.connect('grocery_store.db')
c = conn.cursor()

c.execute('''CREATE TABLE IF NOT EXISTS users
             (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT)''')
c.execute('''CREATE TABLE IF NOT EXISTS stock
             (id INTEGER PRIMARY KEY, item TEXT, quantity INTEGER)''')
conn.commit()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def show_signup_frame():
    login_frame.pack_forget()
    signup_frame.pack(fill='both', expand=True)

def show_login_frame():
    signup_frame.pack_forget()
    login_frame.pack(fill='both', expand=True)

def show_stock_frame():
    login_frame.pack_forget()
    stock_frame.pack(fill='both', expand=True)
    view_stock()

def signup():
    username = signup_user_entry.get()
    password = signup_password_entry.get()
    hashed_password = hash_password(password)

    try:
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        messagebox.showinfo("Success", "Account created successfully.")
        show_login_frame()
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "Username already exists.")

def login():
    username = user_entry.get()
    password = password_entry.get()
    hashed_password = hash_password(password)

    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = c.fetchone()

    if user and user[2] == hashed_password:
        messagebox.showinfo("Success", "Login successful.")
        show_stock_frame()
    else:
        messagebox.showerror("Error", "Invalid username or password.")

def add_item():
    item = item_entry.get()
    quantity = quantity_entry.get()
    try:
        quantity = int(quantity)
        c.execute("INSERT INTO stock (item, quantity) VALUES (?, ?)", (item, quantity))
        conn.commit()
        messagebox.showinfo("Success", f"{quantity} {item}(s) added to the stock.")
        item_entry.delete(0, END)
        quantity_entry.delete(0, END)
        view_stock()
    except ValueError:
        messagebox.showerror("Error", "Quantity must be a number.")

def update_quantity():
    item = item_entry.get()
    new_quantity = quantity_entry.get()
    try:
        new_quantity = int(new_quantity)
        c.execute("UPDATE stock SET quantity = ? WHERE item = ?", (new_quantity, item))
        conn.commit()
        messagebox.showinfo("Success", f"Quantity of {item} updated to {new_quantity}.")
        item_entry.delete(0, END)
        quantity_entry.delete(0, END)
        view_stock()
    except ValueError:
        messagebox.showerror("Error", "Quantity must be a number.")

def view_stock():
    c.execute("SELECT * FROM stock")
    rows = c.fetchall()
    stock_list.delete(0, END)
    for row in rows:
        stock_list.insert(END, f"{row[1]}: {row[2]}")

def delete_item():
    selected_item = stock_list.get(tk.ACTIVE)
    if selected_item:
        item_name = selected_item.split(":")[0]
        c.execute("DELETE FROM stock WHERE item = ?", (item_name,))
        conn.commit()
        messagebox.showinfo("Success", f"{item_name} deleted from stock.")
        view_stock()
    else:
        messagebox.showerror("Error", "No item selected.")

window = ctk.CTk()
window.geometry("800x600")
window.title('C and K Inventory Management System')

login_frame = ctk.CTkFrame(window)
login_frame.pack(fill='both', expand=True)

user_entry = ctk.CTkEntry(login_frame, width=250, height=50, border_width=1, border_color='#FFA500')
user_entry.insert(0, user_text)
user_entry.bind("<FocusIn>", lambda event: user_entry.delete(0, END) if user_entry.get() == user_text else None)
user_entry.bind("<FocusOut>", lambda event: user_entry.insert(0, user_text) if user_entry.get() == "" else None)
user_entry.place(relx=0.5, rely=0.4, anchor='center')

password_entry = ctk.CTkEntry(login_frame, width=250, height=50, border_width=1, border_color='#FFA500', show='*')
password_entry.insert(0, password_text)
password_entry.bind("<FocusIn>", lambda event: password_entry.delete(0, END) if password_entry.get() == password_text else None)
password_entry.bind("<FocusOut>", lambda event: password_entry.insert(0, password_text) if password_entry.get() == "" else None)
password_entry.place(relx=0.5, rely=0.5, anchor='center')

login_button = ctk.CTkButton(login_frame, text='Log In', font=("Arial", 20, "bold"), corner_radius=10, width=250, height=25, fg_color='#FFA500', command=login)
login_button.place(relx=0.5, rely=0.6, anchor='center')

create_acc_label = ctk.CTkLabel(login_frame, text='Create an account?', font=("Arial", 15), text_color='#FFA500')
create_acc_label.bind("<Button-1>", lambda event: show_signup_frame())
create_acc_label.place(relx=0.5, rely=0.65, anchor='center')

signup_frame = ctk.CTkFrame(window)

signup_user_entry = ctk.CTkEntry(signup_frame, width=250, height=50, border_width=1, border_color='#FFA500')
signup_user_entry.insert(0, signup_user_text)
signup_user_entry.bind("<FocusIn>", lambda event: signup_user_entry.delete(0, END) if signup_user_entry.get() == signup_user_text else None)
signup_user_entry.bind("<FocusOut>", lambda event: signup_user_entry.insert(0, signup_user_text) if signup_user_entry.get() == "" else None)
signup_user_entry.grid(row=0, column=0, padx=20, pady=10)

signup_password_entry = ctk.CTkEntry(signup_frame, width=250, height=50, border_width=1, border_color='#FFA500', show='*')
signup_password_entry.insert(0, signup_password_text)
signup_password_entry.bind("<FocusIn>", lambda event: signup_password_entry.delete(0, END) if signup_password_entry.get() == signup_password_text else None)
signup_password_entry.bind("<FocusOut>", lambda event: signup_password_entry.insert(0, signup_password_text) if signup_password_entry.get() == "" else None)
signup_password_entry.grid(row=1, column=0, padx=20, pady=10)

signup_button = ctk.CTkButton(signup_frame, text='Sign Up', font=("Arial", 20, "bold"), corner_radius=10, width=250, height=25, fg_color='#FFA500', command=signup)
signup_button.grid(row=2, column=0, padx=20, pady=10)

stock_frame = ctk.CTkFrame(window)

item_label = ctk.CTkLabel(stock_frame, text="Item:", text_color='#FFA500')
item_label.grid(row=0, column=0, padx=5, pady=5)
quantity_label = ctk.CTkLabel(stock_frame, text="Quantity:", text_color='#FFA500')
quantity_label.grid(row=0, column=2, padx=10, pady=10)

item_entry = ctk.CTkEntry(stock_frame)
item_entry.grid(row=0, column=1, padx=10, pady=10)
quantity_entry = ctk.CTkEntry(stock_frame,)
quantity_entry.grid(row=0, column=3, padx=10, pady=10)

add_button = tk.Button(stock_frame, height=5, width=5, text="Add Item", command=add_item, bg="#FFA500", fg="white")
add_button.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="WE")
update_button = tk.Button(stock_frame, height=5, width=5, text="Update Quantity", command=update_quantity, bg="#FFA500", fg="white")
update_button.grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky="WE")
view_button = tk.Button(stock_frame, height=5, width=5, text="View Stock", command=view_stock, bg="#FFA500")
view_button.grid(row=4, column=0, columnspan=2, padx=5, pady=5, sticky="WE")

delete_button = tk.Button(stock_frame, height=4, width=4, text="Delete Item", command=delete_item, bg="#FFA500", fg="white")
delete_button.grid(row=0, column=5, columnspan=2, padx=5, pady=5, sticky="WE")

scrollbar = tk.Scrollbar(stock_frame)
scrollbar.grid(row=3, column=6, sticky='ns')

stock_list = tk.Listbox(stock_frame, height=10, width=20, yscrollcommand=scrollbar.set)
stock_list.grid(row=1, column=2, rowspan=4, columnspan=4, padx=10, pady=10, sticky="NSEW")

scrollbar.config(command=stock_list.yview)

stock_frame.grid_rowconfigure(5, weight=1)
stock_frame.grid_columnconfigure(0, weight=2)
stock_frame.grid_columnconfigure(5, weight=2)
stock_frame.grid_columnconfigure(5, weight=2)
stock_frame.grid_columnconfigure(5, weight=2)

window.mainloop()

conn.close()