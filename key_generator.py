from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import secrets

class KeyGenerator:

    def encrypt_key(self, key, pin):
        aes_key = hashlib.sha256(pin.encode()).digest()
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        pad_len = 16 - len(key) % 16
        padded_priv = key + bytes([pad_len] * pad_len)
        encrypted_key = iv + encryptor.update(padded_priv) + encryptor.finalize()

        return encrypted_key

    def save_keys(self, public_key, private_key):
        messagebox.showinfo("Save Private Key", "Choose location to save the encrypted private key (e.g., USB)")
        priv_path = filedialog.asksaveasfilename(defaultextension=".bin", title="Save Encrypted Private Key")

        messagebox.showinfo("Save Public Key", "Choose location to save the public key")
        pub_path = filedialog.asksaveasfilename(defaultextension=".pem", title="Save Public Key")

        if priv_path and pub_path:
            with open(priv_path, 'wb') as priv_file:
                priv_file.write(private_key)
            with open(pub_path, 'wb') as pub_file:
                pub_file.write(public_key)
            messagebox.showinfo("Success", "Keys saved successfully.")
        else:
            messagebox.showwarning("Cancelled", "Key saving cancelled.")

    def serialize_keys(self, public_key, private_key):
        pub_pem = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        priv_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        )

        return pub_pem, priv_pem

    def generate_keys(self, pin):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        public_key = private_key.public_key()

        pub_pem, priv_pem = self.serialize_keys(public_key, private_key)

        encrypted_key = self.encrypt_key(priv_pem, pin)

        self.save_keys(pub_pem, encrypted_key)