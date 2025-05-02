import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import sqlite3
import hashlib
import base64
import os
import secrets
import string
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Define a fallback clipboard function if pyperclip is not available
try:
    import pyperclip
    
    def copy_to_clipboard(text):
        pyperclip.copy(text)
        return True
except ImportError:
    def copy_to_clipboard(text):
        # Fallback clipboard method using Tkinter
        # This is less reliable but works without external dependencies
        try:
            root = tk.Tk()
            root.withdraw()  # Hide the window
            root.clipboard_clear()
            root.clipboard_append(text)
            root.update()  # Required for clipboard to work
            root.destroy()
            return True
        except Exception as e:
            print(f"Clipboard error: {e}")
            return False

class Database:
    def __init__(self):
        self.conn = sqlite3.connect('mindwave_pass.db')
        self.create_tables()
    
    def create_tables(self):
        cursor = self.conn.cursor()
        
        # Create users table to store master password hash and salt
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )
        ''')
        
        # Create credentials table to store encrypted credentials
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY,
            website TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            category TEXT,
            date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        self.conn.commit()
    
    def check_master_password_exists(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        return count > 0
    
    def set_master_password(self, password):
        # Generate a random salt
        salt = os.urandom(16)
        
        # Hash the password with the salt
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000  # Number of iterations
        ).hex()
        
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO users (password_hash, salt) VALUES (?, ?)",
                      (password_hash, salt.hex()))
        self.conn.commit()
        return True
    
    def verify_master_password(self, password):
        cursor = self.conn.cursor()
        cursor.execute("SELECT password_hash, salt FROM users LIMIT 1")
        result = cursor.fetchone()
        
        if not result:
            return False
        
        stored_hash, salt_hex = result
        salt = bytes.fromhex(salt_hex)
        
        # Hash the provided password with the stored salt
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000  # Number of iterations
        ).hex()
        
        # Compare the hashes
        return password_hash == stored_hash
    
    def add_credential(self, website, username, password, category, encryption_key):
        # Encrypt the password
        encrypted_password = encrypt(password, encryption_key)
        
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO credentials (website, username, password, category) VALUES (?, ?, ?, ?)",
            (website, username, encrypted_password, category)
        )
        self.conn.commit()
        return cursor.lastrowid
    
    def get_all_credentials(self, encryption_key):
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, website, username, password, category, date_added FROM credentials ORDER BY website")
        credentials = []
        
        for row in cursor.fetchall():
            id, website, username, encrypted_password, category, date_added = row
            # Decrypt the password
            try:
                decrypted_password = decrypt(encrypted_password, encryption_key)
                credentials.append({
                    'id': id,
                    'website': website,
                    'username': username,
                    'password': decrypted_password,
                    'category': category,
                    'date_added': date_added
                })
            except Exception as e:
                print(f"Error decrypting password for {website}: {e}")
        
        return credentials
    
    def search_credentials(self, search_term, encryption_key):
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT id, website, username, password, category, date_added FROM credentials WHERE website LIKE ? OR username LIKE ? OR category LIKE ?",
            (f"%{search_term}%", f"%{search_term}%", f"%{search_term}%")
        )
        
        credentials = []
        for row in cursor.fetchall():
            id, website, username, encrypted_password, category, date_added = row
            try:
                decrypted_password = decrypt(encrypted_password, encryption_key)
                credentials.append({
                    'id': id,
                    'website': website,
                    'username': username,
                    'password': decrypted_password,
                    'category': category,
                    'date_added': date_added
                })
            except Exception as e:
                print(f"Error decrypting password for {website}: {e}")
        
        return credentials
    
    def update_credential(self, id, website, username, password, category, encryption_key):
        # Encrypt the password
        encrypted_password = encrypt(password, encryption_key)
        
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE credentials SET website=?, username=?, password=?, category=? WHERE id=?",
            (website, username, encrypted_password, category, id)
        )
        self.conn.commit()
        return cursor.rowcount > 0
    
    def delete_credential(self, id):
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM credentials WHERE id=?", (id,))
        self.conn.commit()
        return cursor.rowcount > 0
    
    def close(self):
        self.conn.close()

def derive_key(master_password):
    """Derive an encryption key from the master password"""
    # Use a constant salt for key derivation
    # In a production environment, this should be stored securely
    salt = b'mindwave_pass_salt'
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

def encrypt(data, key):
    """Encrypt data using Fernet symmetric encryption"""
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

def decrypt(encrypted_data, key):
    """Decrypt data using Fernet symmetric encryption"""
    f = Fernet(key)
    return f.decrypt(encrypted_data.encode()).decode()

def generate_password(length=16, use_uppercase=True, use_lowercase=True, 
                     use_digits=True, use_symbols=True):
    """Generate a secure random password"""
    # Define character sets
    uppercase_chars = string.ascii_uppercase if use_uppercase else ""
    lowercase_chars = string.ascii_lowercase if use_lowercase else ""
    digit_chars = string.digits if use_digits else ""
    symbol_chars = string.punctuation if use_symbols else ""
    
    # Combine all selected character sets
    all_chars = uppercase_chars + lowercase_chars + digit_chars + symbol_chars
    
    if not all_chars:
        raise ValueError("At least one character set must be selected")
    
    # Ensure at least one character from each selected set
    password = []
    if use_uppercase:
        password.append(secrets.choice(uppercase_chars))
    if use_lowercase:
        password.append(secrets.choice(lowercase_chars))
    if use_digits:
        password.append(secrets.choice(digit_chars))
    if use_symbols:
        password.append(secrets.choice(symbol_chars))
    
    # Fill the rest of the password with random characters
    remaining_length = length - len(password)
    if remaining_length > 0:
        password.extend(secrets.choice(all_chars) for _ in range(remaining_length))
    
    # Shuffle the password to avoid predictable patterns
    secrets.SystemRandom().shuffle(password)
    
    return ''.join(password)

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("MindWave Pass")
        self.root.geometry("800x600")
        self.root.minsize(800, 600)
        
        # Set theme and style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Arial', 10))
        self.style.configure('TButton', font=('Arial', 10))
        self.style.configure('Header.TLabel', font=('Arial', 16, 'bold'))
        
        # Initialize database
        self.db = Database()
        
        # Initialize encryption key (will be set after master password verification)
        self.encryption_key = None
        
        # Check if master password exists
        if self.db.check_master_password_exists():
            self.show_login_screen()
        else:
            self.show_create_master_password_screen()
    
    def show_login_screen(self):
        # Clear the root window
        for widget in self.root.winfo_children():
            widget.destroy()
        
        frame = ttk.Frame(self.root, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Logo and title
        title_label = ttk.Label(frame, text="MindWave Pass", style='Header.TLabel')
        title_label.pack(pady=(0, 20))
        
        # Master password entry
        ttk.Label(frame, text="Enter Master Password:").pack(pady=(10, 5))
        self.master_password_entry = ttk.Entry(frame, show="•", width=30)
        self.master_password_entry.pack(pady=(0, 20))
        self.master_password_entry.focus()
        
        # Login button
        login_button = ttk.Button(frame, text="Login", command=self.verify_master_password)
        login_button.pack(pady=10)
        
        # Bind Enter key to login
        self.master_password_entry.bind("<Return>", lambda event: self.verify_master_password())
    
    def show_create_master_password_screen(self):
        # Clear the root window
        for widget in self.root.winfo_children():
            widget.destroy()
        
        frame = ttk.Frame(self.root, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Logo and title
        title_label = ttk.Label(frame, text="MindWave Pass", style='Header.TLabel')
        title_label.pack(pady=(0, 20))
        
        # Instructions
        ttk.Label(frame, text="Create a strong master password to secure your vault.").pack(pady=(10, 20))
        
        # Master password entry
        ttk.Label(frame, text="Enter Master Password:").pack(pady=(10, 5))
        self.new_master_password_entry = ttk.Entry(frame, show="•", width=30)
        self.new_master_password_entry.pack(pady=(0, 10))
        
        # Confirm master password entry
        ttk.Label(frame, text="Confirm Master Password:").pack(pady=(10, 5))
        self.confirm_master_password_entry = ttk.Entry(frame, show="•", width=30)
        self.confirm_master_password_entry.pack(pady=(0, 20))
        
        # Create button
        create_button = ttk.Button(frame, text="Create Vault", command=self.create_master_password)
        create_button.pack(pady=10)
        
        # Bind Enter key to create
        self.confirm_master_password_entry.bind("<Return>", lambda event: self.create_master_password())
    
    def create_master_password(self):
        password = self.new_master_password_entry.get()
        confirm_password = self.confirm_master_password_entry.get()
        
        if not password:
            messagebox.showerror("Error", "Master password cannot be empty")
            return
        
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        if len(password) < 8:
            messagebox.showerror("Error", "Master password must be at least 8 characters long")
            return
        
        # Set the master password
        if self.db.set_master_password(password):
            # Derive encryption key from master password
            self.encryption_key = derive_key(password)
            messagebox.showinfo("Success", "Master password created successfully")
            self.show_dashboard()
        else:
            messagebox.showerror("Error", "Failed to create master password")
    
    def verify_master_password(self):
        password = self.master_password_entry.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter your master password")
            return
        
        if self.db.verify_master_password(password):
            # Derive encryption key from master password
            self.encryption_key = derive_key(password)
            self.show_dashboard()
        else:
            messagebox.showerror("Error", "Incorrect master password")
    
    def show_dashboard(self):
        # Clear the root window
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Create main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create header frame
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Title
        title_label = ttk.Label(header_frame, text="MindWave Pass", style='Header.TLabel')
        title_label.pack(side=tk.LEFT, padx=10)
        
        # Search frame
        search_frame = ttk.Frame(header_frame)
        search_frame.pack(side=tk.RIGHT, padx=10)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 5))
        self.search_entry = ttk.Entry(search_frame, width=20)
        self.search_entry.pack(side=tk.LEFT, padx=(0, 5))
        self.search_entry.bind("<KeyRelease>", self.search_credentials)
        
        # Create button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # Add credential button
        add_button = ttk.Button(button_frame, text="Add New", command=self.show_add_credential_dialog)
        add_button.pack(side=tk.LEFT, padx=5)
        
        # Generate password button
        generate_button = ttk.Button(button_frame, text="Generate Password", command=self.show_password_generator)
        generate_button.pack(side=tk.LEFT, padx=5)
        
        # Logout button
        logout_button = ttk.Button(button_frame, text="Logout", command=self.logout)
        logout_button.pack(side=tk.RIGHT, padx=5)
        
        # Create credentials frame
        credentials_frame = ttk.Frame(main_frame)
        credentials_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create treeview for credentials
        columns = ("website", "username", "category", "date_added")
        self.credentials_tree = ttk.Treeview(credentials_frame, columns=columns, show="headings")
        
        # Define headings
        self.credentials_tree.heading("website", text="Website/App")
        self.credentials_tree.heading("username", text="Username")
        self.credentials_tree.heading("category", text="Category")
        self.credentials_tree.heading("date_added", text="Date Added")
        
        # Define columns
        self.credentials_tree.column("website", width=150)
        self.credentials_tree.column("username", width=150)
        self.credentials_tree.column("category", width=100)
        self.credentials_tree.column("date_added", width=150)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(credentials_frame, orient=tk.VERTICAL, command=self.credentials_tree.yview)
        self.credentials_tree.configure(yscroll=scrollbar.set)
        
        # Pack treeview and scrollbar
        self.credentials_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind double-click event to view credential
        self.credentials_tree.bind("<Double-1>", self.view_credential)
        
        # Bind right-click event for context menu
        self.credentials_tree.bind("<Button-3>", self.show_context_menu)
        
        # Load credentials
        self.load_credentials()
    
    def load_credentials(self):
        # Clear existing items
        for item in self.credentials_tree.get_children():
            self.credentials_tree.delete(item)
        
        # Get all credentials
        credentials = self.db.get_all_credentials(self.encryption_key)
        
        # Add credentials to treeview
        for cred in credentials:
            self.credentials_tree.insert("", tk.END, iid=cred['id'], values=(
                cred['website'],
                cred['username'],
                cred['category'],
                cred['date_added']
            ))
    
    def search_credentials(self, event=None):
        search_term = self.search_entry.get()
        
        # Clear existing items
        for item in self.credentials_tree.get_children():
            self.credentials_tree.delete(item)
        
        if not search_term:
            # If search term is empty, load all credentials
            self.load_credentials()
            return
        
        # Search credentials
        credentials = self.db.search_credentials(search_term, self.encryption_key)
        
        # Add matching credentials to treeview
        for cred in credentials:
            self.credentials_tree.insert("", tk.END, iid=cred['id'], values=(
                cred['website'],
                cred['username'],
                cred['category'],
                cred['date_added']
            ))
    
    def show_add_credential_dialog(self):
        # Create a new top-level window
        dialog = tk.Toplevel(self.root)
        dialog.title("Add New Credential")
        dialog.geometry("400x350")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Create form
        frame = ttk.Frame(dialog, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Website/App
        ttk.Label(frame, text="Website/App:").grid(row=0, column=0, sticky=tk.W, pady=5)
        website_entry = ttk.Entry(frame, width=30)
        website_entry.grid(row=0, column=1, pady=5)
        website_entry.focus()
        
        # Username
        ttk.Label(frame, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=5)
        username_entry = ttk.Entry(frame, width=30)
        username_entry.grid(row=1, column=1, pady=5)
        
        # Password
        ttk.Label(frame, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        password_frame = ttk.Frame(frame)
        password_frame.grid(row=2, column=1, pady=5, sticky=tk.W)
        
        password_entry = ttk.Entry(password_frame, width=30, show="•")
        password_entry.pack(side=tk.LEFT)
        
        # Toggle password visibility
        def toggle_password_visibility():
            if password_entry['show'] == '•':
                password_entry['show'] = ''
                toggle_button['text'] = 'Hide'
            else:
                password_entry['show'] = '•'
                toggle_button['text'] = 'Show'
        
        toggle_button = ttk.Button(password_frame, text="Show", width=5, command=toggle_password_visibility)
        toggle_button.pack(side=tk.LEFT, padx=5)
        
        # Generate password button
        def generate_and_insert_password():
            password = generate_password()
            password_entry.delete(0, tk.END)
            password_entry.insert(0, password)
        
        generate_button = ttk.Button(frame, text="Generate Password", command=generate_and_insert_password)
        generate_button.grid(row=3, column=1, pady=5, sticky=tk.W)
        
        # Category
        ttk.Label(frame, text="Category:").grid(row=4, column=0, sticky=tk.W, pady=5)
        category_entry = ttk.Entry(frame, width=30)
        category_entry.grid(row=4, column=1, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=5, column=0, columnspan=2, pady=20)
        
        def save_credential():
            website = website_entry.get()
            username = username_entry.get()
            password = password_entry.get()
            category = category_entry.get()
            
            if not website or not username or not password:
                messagebox.showerror("Error", "Website, username, and password are required")
                return
            
            # Add credential to database
            self.db.add_credential(website, username, password, category, self.encryption_key)
            
            # Close dialog
            dialog.destroy()
            
            # Reload credentials
            self.load_credentials()
            
            messagebox.showinfo("Success", "Credential added successfully")
        
        save_button = ttk.Button(button_frame, text="Save", command=save_credential)
        save_button.pack(side=tk.LEFT, padx=5)
        
        cancel_button = ttk.Button(button_frame, text="Cancel", command=dialog.destroy)
        cancel_button.pack(side=tk.LEFT, padx=5)
    
    def view_credential(self, event=None):
        # Get selected item
        selected_id = self.credentials_tree.focus()
        if not selected_id:
            return
        
        # Get credential details
        credentials = self.db.get_all_credentials(self.encryption_key)
        credential = next((c for c in credentials if str(c['id']) == str(selected_id)), None)
        
        if not credential:
            return
        
        # Create a new top-level window
        dialog = tk.Toplevel(self.root)
        dialog.title("View Credential")
        dialog.geometry("400x350")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Create form
        frame = ttk.Frame(dialog, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Website/App
        ttk.Label(frame, text="Website/App:").grid(row=0, column=0, sticky=tk.W, pady=5)
        website_entry = ttk.Entry(frame, width=30)
        website_entry.insert(0, credential['website'])
        website_entry.grid(row=0, column=1, pady=5)
        
        # Username
        ttk.Label(frame, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=5)
        username_frame = ttk.Frame(frame)
        username_frame.grid(row=1, column=1, pady=5, sticky=tk.W)
        
        username_entry = ttk.Entry(username_frame, width=30)
        username_entry.insert(0, credential['username'])
        username_entry.pack(side=tk.LEFT)
        
        # Copy username button
        def copy_username():
            if copy_to_clipboard(username_entry.get()):
                messagebox.showinfo("Copied", "Username copied to clipboard")
            else:
                messagebox.showerror("Error", "Failed to copy to clipboard")
        
        copy_username_button = ttk.Button(username_frame, text="Copy", width=5, command=copy_username)
        copy_username_button.pack(side=tk.LEFT, padx=5)
        
        # Password
        ttk.Label(frame, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        password_frame = ttk.Frame(frame)
        password_frame.grid(row=2, column=1, pady=5, sticky=tk.W)
        
        password_entry = ttk.Entry(password_frame, width=30, show="•")
        password_entry.insert(0, credential['password'])
        password_entry.pack(side=tk.LEFT)
        
        # Toggle password visibility
        def toggle_password_visibility():
            if password_entry['show'] == '•':
                password_entry['show'] = ''
                toggle_button['text'] = 'Hide'
            else:
                password_entry['show'] = '•'
                toggle_button['text'] = 'Show'
        
        toggle_button = ttk.Button(password_frame, text="Show", width=5, command=toggle_password_visibility)
        toggle_button.pack(side=tk.LEFT, padx=5)
        
        # Copy password button
        def copy_password():
            if copy_to_clipboard(password_entry.get()):
                messagebox.showinfo("Copied", "Password copied to clipboard")
            else:
                messagebox.showerror("Error", "Failed to copy to clipboard")
        
        copy_password_button = ttk.Button(frame, text="Copy Password", command=copy_password)
        copy_password_button.grid(row=3, column=1, pady=5, sticky=tk.W)
        
        # Category
        ttk.Label(frame, text="Category:").grid(row=4, column=0, sticky=tk.W, pady=5)
        category_entry = ttk.Entry(frame, width=30)
        category_entry.insert(0, credential['category'] or "")
        category_entry.grid(row=4, column=1, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=5, column=0, columnspan=2, pady=20)
        
        def update_credential():
            website = website_entry.get()
            username = username_entry.get()
            password = password_entry.get()
            category = category_entry.get()
            
            if not website or not username or not password:
                messagebox.showerror("Error", "Website, username, and password are required")
                return
            
            # Update credential in database
            self.db.update_credential(credential['id'], website, username, password, category, self.encryption_key)
            
            # Close dialog
            dialog.destroy()
            
            # Reload credentials
            self.load_credentials()
            
            messagebox.showinfo("Success", "Credential updated successfully")
        
        save_button = ttk.Button(button_frame, text="Update", command=update_credential)
        save_button.pack(side=tk.LEFT, padx=5)
        
        def delete_credential():
            if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this credential?"):
                # Delete credential from database
                self.db.delete_credential(credential['id'])
                
                # Close dialog
                dialog.destroy()
                
                # Reload credentials
                self.load_credentials()
                
                messagebox.showinfo("Success", "Credential deleted successfully")
        
        delete_button = ttk.Button(button_frame, text="Delete", command=delete_credential)
        delete_button.pack(side=tk.LEFT, padx=5)
        
        close_button = ttk.Button(button_frame, text="Close", command=dialog.destroy)
        close_button.pack(side=tk.LEFT, padx=5)
    
    def show_context_menu(self, event):
        # Get selected item
        selected_id = self.credentials_tree.identify_row(event.y)
        if not selected_id:
            return
        
        # Select the item
        self.credentials_tree.selection_set(selected_id)
        self.credentials_tree.focus(selected_id)
        
        # Create context menu
        context_menu = tk.Menu(self.root, tearoff=0)
        
        # Add menu items
        context_menu.add_command(label="View/Edit", command=self.view_credential)
        
        # Get credential details for copy operations
        credentials = self.db.get_all_credentials(self.encryption_key)
        credential = next((c for c in credentials if str(c['id']) == str(selected_id)), None)
        
        if credential:
            def copy_username():
                if copy_to_clipboard(credential['username']):
                    messagebox.showinfo("Copied", "Username copied to clipboard")
                else:
                    messagebox.showerror("Error", "Failed to copy to clipboard")
            
            def copy_password():
                if copy_to_clipboard(credential['password']):
                    messagebox.showinfo("Copied", "Password copied to clipboard")
                else:
                    messagebox.showerror("Error", "Failed to copy to clipboard")
            
            context_menu.add_command(label="Copy Username", command=copy_username)
            context_menu.add_command(label="Copy Password", command=copy_password)
        
        context_menu.add_separator()
        
        def delete_credential():
            if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this credential?"):
                # Delete credential from database
                self.db.delete_credential(selected_id)
                
                # Reload credentials
                self.load_credentials()
                
                messagebox.showinfo("Success", "Credential deleted successfully")
        
        context_menu.add_command(label="Delete", command=delete_credential)
        
        # Display context menu
        context_menu.tk_popup(event.x_root, event.y_root)
    
    def show_password_generator(self):
        # Create a new top-level window
        dialog = tk.Toplevel(self.root)
        dialog.title("Password Generator")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Create form
        frame = ttk.Frame(dialog, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Password length
        ttk.Label(frame, text="Password Length:").grid(row=0, column=0, sticky=tk.W, pady=5)
        length_var = tk.IntVar(value=16)
        length_spinbox = ttk.Spinbox(frame, from_=8, to=64, textvariable=length_var, width=5)
        length_spinbox.grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # Character sets
        ttk.Label(frame, text="Include:").grid(row=1, column=0, sticky=tk.W, pady=5)
        
        options_frame = ttk.Frame(frame)
        options_frame.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        uppercase_var = tk.BooleanVar(value=True)
        uppercase_check = ttk.Checkbutton(options_frame, text="Uppercase (A-Z)", variable=uppercase_var)
        uppercase_check.pack(anchor=tk.W)
        
        lowercase_var = tk.BooleanVar(value=True)
        lowercase_check = ttk.Checkbutton(options_frame, text="Lowercase (a-z)", variable=lowercase_var)
        lowercase_check.pack(anchor=tk.W)
        
        digits_var = tk.BooleanVar(value=True)
        digits_check = ttk.Checkbutton(options_frame, text="Digits (0-9)", variable=digits_var)
        digits_check.pack(anchor=tk.W)
        
        symbols_var = tk.BooleanVar(value=True)
        symbols_check = ttk.Checkbutton(options_frame, text="Symbols (!@#$%^&*)", variable=symbols_var)
        symbols_check.pack(anchor=tk.W)
        
        # Generated password
        ttk.Label(frame, text="Generated Password:").grid(row=2, column=0, sticky=tk.W, pady=(20, 5))
        
        password_frame = ttk.Frame(frame)
        password_frame.grid(row=2, column=1, pady=(20, 5), sticky=tk.W)
        
        password_var = tk.StringVar()
        password_entry = ttk.Entry(password_frame, textvariable=password_var, width=30)
        password_entry.pack(side=tk.LEFT)
        
        # Generate password
        def generate():
            try:
                password = generate_password(
                    length=length_var.get(),
                    use_uppercase=uppercase_var.get(),
                    use_lowercase=lowercase_var.get(),
                    use_digits=digits_var.get(),
                    use_symbols=symbols_var.get()
                )
                password_var.set(password)
            except ValueError as e:
                messagebox.showerror("Error", str(e))
        
        # Copy password
        def copy_to_clipboard_handler():
            if password_var.get():
                if copy_to_clipboard(password_var.get()):
                    messagebox.showinfo("Copied", "Password copied to clipboard")
                else:
                    messagebox.showerror("Error", "Failed to copy to clipboard")
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=20)
        
        generate_button = ttk.Button(button_frame, text="Generate", command=generate)
        generate_button.pack(side=tk.LEFT, padx=5)
        
        copy_button = ttk.Button(button_frame, text="Copy to Clipboard", command=copy_to_clipboard_handler)
        copy_button.pack(side=tk.LEFT, padx=5)
        
        close_button = ttk.Button(button_frame, text="Close", command=dialog.destroy)
        close_button.pack(side=tk.LEFT, padx=5)
        
        # Generate initial password
        generate()
    
    def logout(self):
        # Clear encryption key
        self.encryption_key = None
        
        # Show login screen
        self.show_login_screen()

def main():
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()