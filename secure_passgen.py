import tkinter as tk
from tkinter import messagebox, ttk, simpledialog
import random
import string
import hashlib
import requests
import json
import os
from datetime import datetime, timedelta
from cryptography.fernet import Fernet

# ------------------------------
# Constants and Globals
# ------------------------------
APP_TITLE = "Secure Password Generator"
HISTORY_LIMIT = 20
PASSWORD_EXPIRY_DAYS = 30
DATA_FILE = "passwords.enc"
KEY_FILE = "key.key"

# Theme colors
LIGHT_BG = "#F0F0F0"
LIGHT_FG = "#202020"
DARK_BG = "#2E3440"
DARK_FG = "#D8DEE9"

# ------------------------------
# Encryption Helpers
# ------------------------------
def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
    else:
        with open(KEY_FILE, 'rb') as f:
            key = f.read()
    return key

key = load_key()
fernet = Fernet(key)

def encrypt_data(data):
    return fernet.encrypt(data.encode())

def decrypt_data(token):
    return fernet.decrypt(token).decode()

# ------------------------------
# Password Generator and Checker
# ------------------------------
def generate_password(length=12, use_special=True):
    chars = string.ascii_letters + string.digits
    if use_special:
        chars += string.punctuation
    password = ''.join(random.choice(chars) for _ in range(length))
    return password

def check_password_breach(password):
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            raise RuntimeError("API error")
        hashes = (line.split(":") for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return int(count)
        return 0
    except Exception as e:
        return -1  # error

def password_strength(password):
    length = len(password)
    categories = [any(c.islower() for c in password),
                  any(c.isupper() for c in password),
                  any(c.isdigit() for c in password),
                  any(c in string.punctuation for c in password)]
    score = length + sum(categories)*5
    if score > 20:
        return "Strong", "green"
    elif score > 12:
        return "Medium", "orange"
    else:
        return "Weak", "red"

# ------------------------------
# Password History and Storage
# ------------------------------
def load_history():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "rb") as f:
                encrypted = f.read()
            decrypted = decrypt_data(encrypted)
            return json.loads(decrypted)
        except Exception:
            return []
    return []

def save_history(history):
    data = json.dumps(history)
    encrypted = encrypt_data(data)
    with open(DATA_FILE, "wb") as f:
        f.write(encrypted)

# ------------------------------
# GUI Application
# ------------------------------
class PasswordApp:
    def __init__(self, master):
        self.master = master
        self.master.title(APP_TITLE)
        self.master.geometry("600x500")
        self.master.resizable(False, False)

        # Theme state
        self.dark_mode = True
        self.bg_color = DARK_BG
        self.fg_color = DARK_FG

        # Password expiry tracker
        self.last_generated = None

        # Password history
        self.history = load_history()

        self.create_widgets()
        self.apply_theme()
        self.update_history_list()
        self.check_expiry_reminder()

    def create_widgets(self):
        self.frame_main = tk.Frame(self.master, bg=self.bg_color)
        self.frame_main.pack(fill="both", expand=True, padx=10, pady=10)

        # Password display
        tk.Label(self.frame_main, text="Generated Password:", bg=self.bg_color, fg=self.fg_color).grid(row=0, column=0, sticky="w")
        self.password_var = tk.StringVar()
        self.entry_password = tk.Entry(self.frame_main, textvariable=self.password_var, font=("Courier", 14), 
                                       width=40, bg="#4C566A", fg="white", bd=0, highlightthickness=0)
        self.entry_password.grid(row=1, column=0, columnspan=3, pady=5)

        self.btn_copy = tk.Button(self.frame_main, text="Copy Password", command=self.copy_password, bg="#5E81AC", fg="white", bd=0)
        self.btn_copy.grid(row=1, column=3, padx=5)

        # Length input
        tk.Label(self.frame_main, text="Password Length:", bg=self.bg_color, fg=self.fg_color).grid(row=2, column=0, sticky="w", pady=(10,0))
        self.length_entry = tk.Entry(self.frame_main, bg="#4C566A", fg="white", bd=0, highlightthickness=0, width=5)
        self.length_entry.insert(0, "12")
        self.length_entry.grid(row=3, column=0, sticky="w")

        # Symbols checkbox
        self.symbol_var = tk.BooleanVar(value=True)
        self.chk_symbols = tk.Checkbutton(self.frame_main, text="Include Special Characters", variable=self.symbol_var,
                                          bg=self.bg_color, fg=self.fg_color, selectcolor=self.bg_color)
        self.chk_symbols.grid(row=3, column=1, sticky="w", padx=10)

        # Generate button
        self.btn_generate = tk.Button(self.frame_main, text="Generate Password", command=self.generate_and_check,
                                      bg="#5E81AC", fg="white", bd=0, width=20)
        self.btn_generate.grid(row=3, column=2, sticky="w", padx=10)

        # Password strength
        self.strength_var = tk.StringVar(value="Strength: ")
        self.lbl_strength = tk.Label(self.frame_main, textvariable=self.strength_var, bg=self.bg_color, fg=self.fg_color, font=("Arial", 12))
        self.lbl_strength.grid(row=4, column=0, columnspan=4, sticky="w", pady=10)

        # Breach check for user input
        tk.Label(self.frame_main, text="Check Your Own Password:", bg=self.bg_color, fg=self.fg_color).grid(row=5, column=0, sticky="w", pady=(20,0))
        self.custom_pass_var = tk.StringVar()
        self.entry_custom = tk.Entry(self.frame_main, textvariable=self.custom_pass_var, font=("Courier", 12),
                                     width=30, bg="#4C566A", fg="white", bd=0, highlightthickness=0)
        self.entry_custom.grid(row=6, column=0, columnspan=2, sticky="w", pady=5)
        self.btn_check_custom = tk.Button(self.frame_main, text="Check Breach", command=self.check_custom_password,
                                          bg="#5E81AC", fg="white", bd=0)
        self.btn_check_custom.grid(row=6, column=2, padx=5)

        self.custom_result_var = tk.StringVar()
        self.lbl_custom_result = tk.Label(self.frame_main, textvariable=self.custom_result_var, bg=self.bg_color, fg=self.fg_color)
        self.lbl_custom_result.grid(row=7, column=0, columnspan=4, sticky="w", pady=5)

        # Password History
        tk.Label(self.frame_main, text="Password History:", bg=self.bg_color, fg=self.fg_color).grid(row=8, column=0, sticky="w", pady=(20,0))
        self.lst_history = tk.Listbox(self.frame_main, height=6, width=40, bg="#4C566A", fg="white", bd=0, highlightthickness=0)
        self.lst_history.grid(row=9, column=0, columnspan=3, sticky="w")

        self.btn_clear_history = tk.Button(self.frame_main, text="Clear History", command=self.clear_history,
                                           bg="#BF616A", fg="white", bd=0)
        self.btn_clear_history.grid(row=9, column=3, sticky="n", padx=5)

        # Theme toggle
        self.btn_theme = tk.Button(self.frame_main, text="Toggle Light/Dark Mode", command=self.toggle_theme,
                                   bg="#81A1C1", fg="white", bd=0)
        self.btn_theme.grid(row=10, column=0, columnspan=4, pady=20)

    def apply_theme(self):
        bg = DARK_BG if self.dark_mode else LIGHT_BG
        fg = DARK_FG if self.dark_mode else LIGHT_FG
        self.bg_color = bg
        self.fg_color = fg
        self.master.configure(bg=bg)
        self.frame_main.configure(bg=bg)

        # Widgets that are not labels
        widgets = [self.lst_history, self.chk_symbols, self.btn_generate, self.btn_copy, self.btn_clear_history, self.btn_theme]
        for w in widgets:
            try:
                w.configure(bg=bg, fg=fg)
            except:
                pass

        # Labels (set bg and fg separately)
        label_widgets = [self.lbl_strength, self.lbl_custom_result]
        for lbl in label_widgets:
            try:
                if self.dark_mode:
                    lbl.configure(bg=DARK_BG, fg=DARK_FG)
                else:
                    lbl.configure(bg=LIGHT_BG, fg=LIGHT_FG)
            except:
                pass

        # Also update all other static labels explicitly:
        for child in self.frame_main.winfo_children():
            if isinstance(child, tk.Label) and child not in label_widgets:
                try:
                    if self.dark_mode:
                        child.configure(bg=DARK_BG, fg=DARK_FG)
                    else:
                        child.configure(bg=LIGHT_BG, fg=LIGHT_FG)
                except:
                    pass

        # Entry widgets background/fg
        entries = [self.entry_password, self.length_entry, self.entry_custom]
        for e in entries:
            e.configure(bg="#4C566A" if self.dark_mode else "#FFFFFF", fg=fg)

    def copy_password(self):
        pwd = self.password_var.get()
        if pwd:
            self.master.clipboard_clear()
            self.master.clipboard_append(pwd)
            messagebox.showinfo("Copied", "Password copied to clipboard!")

    def generate_and_check(self):
        try:
            length = int(self.length_entry.get())
            if length < 4 or length > 64:
                messagebox.showerror("Error", "Length must be between 4 and 64.")
                return
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number for length.")
            return

        use_symbols = self.symbol_var.get()
        pwd = generate_password(length, use_symbols)
        self.password_var.set(pwd)
        self.last_generated = datetime.now()

        # Update strength
        strength_text, strength_color = password_strength(pwd)
        self.strength_var.set(f"Strength: {strength_text}")
        self.lbl_strength.config(fg=strength_color)

        # Check breach
        breach_count = check_password_breach(pwd)
        if breach_count == -1:
            messagebox.showwarning("Warning", "Could not check breach status (network error).")
        elif breach_count > 0:
            messagebox.showwarning("Warning", f"Password breached {breach_count} times!")
        else:
            messagebox.showinfo("Good News", "Password not found in breaches.")

        # Add to history
        self.history.insert(0, {"password": pwd, "date": self.last_generated.isoformat()})
        if len(self.history) > HISTORY_LIMIT:
            self.history = self.history[:HISTORY_LIMIT]
        save_history(self.history)
        self.update_history_list()

    def update_history_list(self):
        self.lst_history.delete(0, tk.END)
        for entry in self.history:
            dt = datetime.fromisoformat(entry["date"]).strftime("%Y-%m-%d %H:%M")
            self.lst_history.insert(tk.END, f"{dt} - {entry['password']}")

    def clear_history(self):
        if messagebox.askyesno("Confirm", "Clear all password history?"):
            self.history = []
            save_history(self.history)
            self.update_history_list()

    def check_custom_password(self):
        pwd = self.custom_pass_var.get()
        if not pwd:
            messagebox.showerror("Error", "Enter a password to check.")
            return
        breach_count = check_password_breach(pwd)
        if breach_count == -1:
            self.custom_result_var.set("Network error during breach check.")
            self.lbl_custom_result.config(fg="orange")
        elif breach_count > 0:
            self.custom_result_var.set(f"⚠️ Password breached {breach_count} times!")
            self.lbl_custom_result.config(fg="red")
        else:
            self.custom_result_var.set("✅ Password not found in breaches.")
            self.lbl_custom_result.config(fg="green")

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self.apply_theme()

    def check_expiry_reminder(self):
        if self.last_generated:
            delta = datetime.now() - self.last_generated
            if delta > timedelta(days=PASSWORD_EXPIRY_DAYS):
                messagebox.showinfo("Reminder", f"Your generated password is over {PASSWORD_EXPIRY_DAYS} days old. Consider generating a new one.")
        self.master.after(24*3600*1000, self.check_expiry_reminder)  # check once a day

# ------------------------------
# Run app
# ------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordApp(root)
    root.mainloop()