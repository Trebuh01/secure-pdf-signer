## @file verifier.py
#  @brief Weryfikator podpisów PDF z GUI opartym na Tkinter.
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from Cryptodome.Hash import SHA256
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
## @class PDFSelector
#  @brief Klasa zawierająca metody do wyboru plików PDF i kluczy publicznych z dysku.
class PDFSelector:
    ## @brief Otwiera okno dialogowe do wyboru podpisanego pliku PDF.
    #  @return Ścieżka do pliku PDF lub None jeśli anulowano.
    @staticmethod
    def pick_signed_pdf():
        path = filedialog.askopenfilename(
            title="Locate Signed PDF",
            filetypes=[("PDF Document", "*.pdf")]
        )
        return path if os.path.exists(path) else None

    ## @brief Otwiera okno dialogowe do wyboru klucza publicznego.
    #  @return Załadowany klucz publiczny lub None.
    @staticmethod
    def pick_public_key():
        path = filedialog.askopenfilename(
            title="Choose Public Key",
            filetypes=[("PEM Format", "*.pem")]
        )
        if not path:
            return None
        with open(path, 'rb') as keyfile:
            key_bytes = keyfile.read()
        return serialization.load_pem_public_key(key_bytes)
## @class PDFSignatureChecker
#  @brief Klasa odpowiadająca za weryfikację podpisów PDF.
class PDFSignatureChecker:
    ## @brief Inicjalizuje weryfikator.
    #  @param document_path Ścieżka do podpisanego PDF.
    #  @param rsa_pub_key Klucz publiczny RSA do weryfikacji.
    def __init__(self, document_path, rsa_pub_key):
        self.pdf_path = document_path
        self.pub_key = rsa_pub_key
        self.data = None
        self.signature = None
        self.content = None

    ## @brief Oddziela treść pliku PDF od podpisu (ostatnie 512 bajtów).
    def split_content_and_signature(self):
        with open(self.pdf_path, 'rb') as f:
            self.data = f.read()
        self.signature = self.data[-512:]
        self.content = self.data[:-512]

    ## @brief Weryfikuje podpis przy pomocy klucza publicznego.
    #  @throw InvalidSignature gdy podpis się nie zgadza.
    def perform_check(self):
        document_hash = SHA256.new(self.content).digest()
        self.pub_key.verify(self.signature, document_hash, padding.PKCS1v15(), hashes.SHA256())
## @class VerifierGui
#  @brief Prosty interfejs graficzny do weryfikacji podpisu pliku PDF.
class VerifierGui(tk.Tk):
    ## @brief Inicjalizacja GUI.
    def __init__(self):
        super().__init__()
        self.title("Document Signature Checker")
        self.geometry("320x160")
        self.resizable(False, False)
        self.setup_interface()

    ## @brief Tworzy przyciski w GUI.
    def setup_interface(self):
        button = tk.Button(self, text="Verify PDF Signature", command=self.start_verification, padx=12, pady=6)
        button.pack(expand=True)

    ## @brief Obsługuje logikę weryfikacji po kliknięciu przycisku.
    def start_verification(self):
        pdf_path = PDFSelector.pick_signed_pdf()
        if not pdf_path:
            messagebox.showwarning("Missing", "Signed document not selected or does not exist.")
            return

        pub_key = PDFSelector.pick_public_key()
        if not pub_key:
            messagebox.showerror("Missing", "Public key was not provided.")
            return

        try:
            verifier = PDFSignatureChecker(pdf_path, pub_key)
            verifier.split_content_and_signature()
            verifier.perform_check()
            messagebox.showinfo("Success", "Signature is VALID. File was not modified.")
        except Exception as err:
            messagebox.showerror("Failed", f"Signature check FAILED:\n{type(err).__name__}: {err}")