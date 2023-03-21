import os, base64
import random
import string
from tkinter import *
from tkinter import messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

def generate_password(length=12):
    characters = string.ascii_letters + string.digits + "!@#"
    return ''.join(random.choice(characters) for _ in range(length))

def derive_key(password, salt):
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    key = kdf.derive(password.encode())
    return Fernet(base64.urlsafe_b64encode(key))

def encrypt_data(data, key):
    return key.encrypt(data.encode()).decode()

def decrypt_data(data, key):
    return key.decrypt(data.encode()).decode()

def save_passwords(data, f_key):
    encrypted_data = {key: encrypt_data(value, f_key) for key, value in data.items()}
    with open('passwords.txt', 'w') as f:
        for key, value in encrypted_data.items():
            f.write(f'{key} {value}\n')

def load_passwords(key):
    if not os.path.exists('passwords.txt'):
        return {}
    with open('passwords.txt', 'r') as f:
        lines = f.readlines()
    decrypted_data = {line.split()[0]: decrypt_data(line.split()[1], key) for line in lines}
    return decrypted_data

def add_password(root_password, website):
    key = derive_key(root_password, salt)
    data = load_passwords(key)
    password = generate_password()
    data[website] = password
    save_passwords(data, key)
    password_text.configure(state="normal")
    password_text.delete(1.0, END)
    password_text.insert(INSERT, f"为网站{website}生成的密码: {password}")
    password_text.configure(state="disabled")


def show_passwords(root_password):
    try:
        key = derive_key(root_password, salt)
        data = load_passwords(key)
    except Exception as e:
        messagebox.showerror("错误", "根密码错误")
        return

    if not data:
        messagebox.showinfo("提示", "无已保存的密码")
        return

    result = ""
    for website, password in data.items():
        result += f"{website}: {password}\n"

    password_text.configure(state="normal")
    password_text.delete(1.0, END)
    password_text.insert(INSERT, result)
    password_text.configure(state="disabled")

def get_salt():
    if not os.path.exists('salt.txt'):
        salt = os.urandom(16)
        with open('salt.txt', 'wb') as f:
            f.write(salt)
    else:
        with open('salt.txt', 'rb') as f:
            salt = f.read()
    return salt

def main():
    global salt, password_text
    salt = get_salt()

    def on_add_click():
        website = website_entry.get()
        if not website:
            messagebox.showerror("错误", "请输入网站名称")
            return
        root_password = password_entry.get()
        if not root_password:
            messagebox.showerror("错误", "请输入根密码")
            return
        add_password(root_password, website)

    def on_show_click():
        root_password = password_entry.get()
        if not root_password:
            messagebox.showerror("错误", "请输入根密码")
            return
        show_passwords(root_password)

    window = Tk()
    window.title("密码管理器")
    window.geometry("600x300")  # 调整窗口尺寸

    Label(window, text="网站名称：").grid(row=0, column=0, padx=(10, 0), pady=(10, 0))
    website_entry = Entry(window)
    website_entry.grid(row=0, column=1, padx=(0, 10), pady=(10, 0))

    Label(window, text="根密码：").grid(row=1, column=0, padx=(10, 0))
    password_entry = Entry(window, show="*")
    password_entry.grid(row=1, column=1, padx=(0, 10))

    add_button = Button(window, text="添加新密码", command=on_add_click)
    add_button.grid(row=2, column=0, padx=(10, 0), pady=10)

    show_button = Button(window, text="显示密码", command=on_show_click)
    show_button.grid(row=2, column=1, padx=(0, 10), pady=10)

    frame = Frame(window)
    frame.grid(row=3, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

    scrollbar = Scrollbar(frame)
    scrollbar.pack(side=RIGHT, fill=Y)

    password_text = Text(frame, wrap=WORD, yscrollcommand=scrollbar.set, state="disabled")
    password_text.pack(fill=BOTH, expand=True)

    scrollbar.config(command=password_text.yview)

    window.mainloop()

if __name__ == "__main__":
    main()

