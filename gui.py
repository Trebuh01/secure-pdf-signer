## @file gui.py
#  @brief Główne GUI aplikacji do obsługi podpisu cyfrowego (generowanie, podpisywanie, weryfikacja PDF).
from key_deployment import USBKeyHandler
from signer import SecurePDFSigner
from verifier import VerifierGui
import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog, scrolledtext
from utils import DigitalSigner

## @class SignatureInterface
#  @brief Główne okno GUI z wyborem jednej z trzech operacji.
class SignatureInterface(tk.Tk):
    ## @brief Konstruktor inicjalizuje główne okno i przyciski.
    def __init__(self):
        super().__init__()
        self.title("Signature Project")
        self.geometry("400x300")
        self.configure(bg="#f0f0f0")

        self.create_widgets()

    ## @brief Tworzy przyciski do generowania kluczy, podpisywania i weryfikacji.
    def create_widgets(self):
        tk.Label(self, text="Choose an operation:", font=("Segoe UI", 12)).pack(pady=20)

        tk.Button(
            self,
            text="Generate RSA Keys",
            font=("Segoe UI", 10),
            width=30,
            command=self.open_key_window
        ).pack(pady=10)

        tk.Button(
            self,
            text="Sign PDF Document",
            font=("Segoe UI", 10),
            width=30,
            command=self.open_signer_window
        ).pack(pady=10)

        tk.Button(
            self,
            text="Verify PDF Signature",
            font=("Segoe UI", 10),
            width=30,
            command=self.open_verifier_window
        ).pack(pady=10)

    ## @brief Otwiera nowe okno do generowania kluczy RSA.
    def open_key_window(self):
        window = tk.Toplevel(self)
        window.title("RSA Key Generation")
        window.geometry("500x300")
        gui = RSAKeyCreator(window)
        USBKeyHandler(gui).run()

    ## @brief Otwiera okno do podpisywania plików PDF.
    def open_signer_window(self):
        gui = PDFSignerWindow()
        signer_interface = SecurePDFSigner(gui)
        signer_interface.run()

    ## @brief Otwiera okno do weryfikacji podpisów cyfrowych.
    def open_verifier_window(self):
        VerifierGui().mainloop()

## @class RSAKeyCreator
#  @brief GUI do generowania i zapisu kluczy RSA.
class RSAKeyCreator:
    ## @brief Konstruktor inicjalizuje okno logu.
    def __init__(self, root):
        self.root = root
        self.console = tk.Text(self.root, wrap=tk.WORD)
        self.console.pack(expand=True, fill=tk.BOTH)

    ## @brief Wyświetla wiadomość w logu.
    #  @param text Tekst do wyświetlenia.
    def log(self, text):
        self.console.insert(tk.END, text + "\n")
        self.console.see(tk.END)
        print(text)

    ## @brief Pyta użytkownika o 4-cyfrowy PIN.
    #  @return PIN jako string lub None.
    def get_pin_from_user(self):
        while True:
            pin = simpledialog.askstring("Enter PIN", "Provide a 4-digit PIN:", parent=self.root, show="*")
            if pin is None:
                return None
            if pin.isdigit() and len(pin) == 4:
                return pin
            messagebox.showwarning("Invalid Input", "PIN must be exactly 4 digits.")

    ## @brief Pokazuje okno wyboru lokalizacji zapisu klucza publicznego.
    #  @return Ścieżka zapisu lub None.
    def get_file_destination_from_user(self):
        destination = filedialog.asksaveasfilename(
            defaultextension=".pem",
            filetypes=[("PEM Files", "*.pem")],
            title="Choose Location for Public Key"
        )
        return destination if destination else None

    def after(self, delay, callback):
        self.root.after(delay, callback)

    def mainloop(self):
        self.root.mainloop()

## @class PDFSignerWindow
#  @brief Okno GUI do podpisywania plików PDF przy użyciu klucza prywatnego.
class PDFSignerWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.geometry("620x410")
        self.title("Signer")

        self.display = scrolledtext.ScrolledText(self, wrap=tk.WORD)
        self.display.pack(fill=tk.BOTH, expand=True)

        self.log_msg("Initializing device search...")

    ## @brief Dodaje wiadomość do logu GUI i konsoli.
    def log_msg(self, text):
        self.display.insert(tk.END, text + "\n")
        self.display.see(tk.END)
        print(text)

    ## @brief Wywołuje proces wyboru pliku i jego podpisania.
    #  @param decrypted_key Odszyfrowany klucz prywatny RSA.
    def sign_file_dialog(self, decrypted_key):
        self.after(0, lambda: self.select_and_sign(decrypted_key))

    ## @brief Wybiera plik PDF, podpisuje go i zapisuje podpisaną wersję.
    #  @param signer_key Klucz prywatny do podpisu.
    def select_and_sign(self, signer_key):
        pdf_input = filedialog.askopenfilename(title="Locate PDF Document", filetypes=[("PDF File", "*.pdf")])
        if not pdf_input:
            self.log_msg("No document selected.")
            return

        try:
            with open(pdf_input, 'rb') as doc:
                original_data = doc.read()
            signer = DigitalSigner(signer_key)
            signature = signer.sign_data(original_data)
            final_name = pdf_input.replace(".pdf", "_signed.pdf")
            with open(final_name, 'wb') as result:
                result.write(original_data + signature)
            self.log_msg(f"Signed version saved: {final_name}")
            messagebox.showinfo("Operation Complete", f"File signed:\n{final_name}")
        except Exception as problem:
            self.log_msg(f"Error during signing: {problem}")

    ## @brief Pyta użytkownika o PIN do odszyfrowania klucza.
    def get_pin_from_user(self):
        return simpledialog.askstring("PIN Required", "Input your 4-digit PIN:", show="*", parent=self)