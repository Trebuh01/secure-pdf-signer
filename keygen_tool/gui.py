import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import secrets


def create_keys():
    pin = pin_var.get()
    if not pin:
        messagebox.showerror("Missing PIN", "Please enter a PIN code.")
        return

    # RSA Key Generation
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    public_key = private_key.public_key()

    # Serialize keys
    pub_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    )

    # Encrypt private key with AES (key = SHA256(PIN))
    aes_key = hashlib.sha256(pin.encode()).digest()
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding
    pad_len = 16 - len(priv_pem) % 16
    padded_priv = priv_pem + bytes([pad_len] * pad_len)
    encrypted = iv + encryptor.update(padded_priv) + encryptor.finalize()

    # Save files
    messagebox.showinfo("Save Private Key", "Choose location to save the encrypted private key (e.g., USB)")
    priv_path = filedialog.asksaveasfilename(defaultextension=".bin", title="Save Encrypted Private Key")

    messagebox.showinfo("Save Public Key", "Choose location to save the public key")
    pub_path = filedialog.asksaveasfilename(defaultextension=".pem", title="Save Public Key")

    if priv_path and pub_path:
        with open(priv_path, 'wb') as priv_file:
            priv_file.write(encrypted)
        with open(pub_path, 'wb') as pub_file:
            pub_file.write(pub_pem)
        messagebox.showinfo("Success", "Keys saved successfully.")
    else:
        messagebox.showwarning("Cancelled", "Key saving cancelled.")


# GUI Setup
root = tk.Tk()
root.title("Secure RSA Key Generator")
root.geometry("400x250")
root.resizable(False, False)

style = ttk.Style()
style.configure("TButton", font=("Segoe UI", 10), padding=6)
style.configure("TLabel", font=("Segoe UI", 10))

frame = ttk.Frame(root, padding=20)
frame.pack(fill="both", expand=True)

ttk.Label(frame, text="Enter your secure PIN:").pack(pady=(0, 5))

pin_var = tk.StringVar()
pin_entry = ttk.Entry(frame, textvariable=pin_var, show="*", width=30)
pin_entry.pack(pady=(0, 15))

generate_btn = ttk.Button(frame, text="Generate & Save Keys", command=create_keys)
generate_btn.pack(pady=(0, 10))

footer = ttk.Label(frame, text="RSA-4096 | AES-256 | SHA-256", font=("Segoe UI", 9, "italic"), foreground="gray")
footer.pack(side="bottom", pady=(20, 0))

root.mainloop()
