## @file signer.py
#  @brief Obsługuje podpisywanie dokumentów PDF po odnalezieniu zaszyfrowanego klucza na urządzeniu USB.
import threading
from utils import DriveWatcher, KeyDecryptor
## @class SecurePDFSigner
#  @brief Klasa odpowiedzialna za proces podpisywania PDF przy użyciu zaszyfrowanego klucza RSA z nośnika USB.
class SecurePDFSigner:
    ## @brief Konstruktor klasy.
    #  @param gui Obiekt GUI umożliwiający interakcję z użytkownikiem.
    def __init__(self, gui):
        self.gui = gui

    ## @brief Wypisuje komunikat do GUI.
    #  @param text Tekst do wyświetlenia.
    def log_msg(self, text):
        self.gui.log_msg(text)

    ## @brief Nasłuchuje podłączenia urządzenia z zaszyfrowanym kluczem prywatnym.
    #  Po wykryciu odpowiedniego pliku, rozpoczyna proces podpisywania.
    def device_listener(self):
        detector = DriveWatcher("private_encrypted.pem")
        key_path = detector.wait_for_media()
        self.log_msg(f"Secure token located: {key_path}")
        self.gui.after(0, lambda: self.initiate_signature(key_path))

    ## @brief Odszyfrowuje klucz i uruchamia dialog podpisywania pliku.
    #  @param key_location Ścieżka do zaszyfrowanego klucza prywatnego na pendrive.
    def initiate_signature(self, key_location):
        try:
            with open(key_location, 'rb') as enc_file:
                encrypted_key = enc_file.read()
        except Exception as error:
            self.log_msg(f"Error: {error}")
            return

        pin = self.gui.get_pin_from_user()
        if not pin:
            self.log_msg("PIN entry cancelled")
            return

        try:
            decrypted_key = KeyDecryptor(encrypted_key, pin).get_private_key()
        except Exception as error:
            self.log_msg(f"Decryption error: {error}")
            return

        self.gui.sign_file_dialog(decrypted_key)

    ## @brief Uruchamia wątek nasłuchujący i główną pętlę GUI.
    def run(self):
        threading.Thread(target=self.device_listener, daemon=True).start()
        self.gui.mainloop()
