## @file key_deployment.py
#  @brief Obsługuje generowanie i zapisywanie kluczy RSA na pamięci USB.
import os
import threading
import time

from utils import USBUtility
from utils import RSAKeyHandler
from utils import KeySecurity

## @class USBKeyHandler
#  @brief Klasa zarządzająca procesem tworzenia kluczy RSA i zapisywania ich na urządzeniu USB.
class USBKeyHandler:
    ## @brief Konstruktor klasy.
    #  @param gui Interfejs GUI do obsługi logowania i wejścia od użytkownika.
    def __init__(self, gui):
        self.gui = gui

    ## @brief Wyświetla komunikat w GUI.
    #  @param text Tekst do wyświetlenia.
    def log(self, text):
        self.gui.log(text)

    ## @brief Prosi użytkownika o wprowadzenie PIN-u.
    #  @return PIN jako string lub None jeśli anulowano.
    def request_pin(self):
        return self.gui.get_pin_from_user()

    ## @brief Zapisuje klucz publiczny do wybranej przez użytkownika lokalizacji.
    #  @param public_bytes Bajty z kluczem publicznym.
    #  @return Ścieżka zapisu lub None jeśli anulowano.
    def save_public_key(self, public_bytes):
        destination = self.gui.get_file_destination_from_user()
        USBUtility.write_file(destination, public_bytes)
        self.log(f"Public key saved to: {destination}")
        return destination

    ## @brief Generuje i zapisuje zaszyfrowany klucz prywatny oraz klucz publiczny na USB.
    #  @param drive_path Ścieżka do zamontowanego pendrive’a.
    def deploy_keys_to_usb(self, drive_path):
        self.log(f"New device connected at {drive_path}")
        pin = self.request_pin()
        if pin is None:
            self.log("PIN entry cancelled.")
            return

        rsa_handler = RSAKeyHandler()
        pub_key = rsa_handler.export_public_key()
        priv_key = rsa_handler.export_private_key()

        if not self.save_public_key(pub_key):
            self.log("Operation aborted: public key not saved.")
            return

        encrypted_priv = KeySecurity.encrypt_private_data(priv_key, pin)
        final_path = os.path.join(drive_path, "private_encrypted.pem")

        try:
            USBUtility.write_file(final_path, encrypted_priv)
            self.log(f"Encrypted private key saved at: {final_path}")
        except Exception as e:
            self.log(f"Error writing private key: {e}")

    ## @brief Monitoruje system w poszukiwaniu nowo podłączonych urządzeń USB.
    #  @param known_drives Zestaw już znanych dysków USB.
    def monitor_usb(self, known_drives):
        while True:
            current = USBUtility.list_all_drives()
            added = current - known_drives
            known_drives = current

            for new_drive in added:
                self.gui.after(0, lambda d=new_drive: self.deploy_keys_to_usb(d))

            time.sleep(1)

    ## @brief Uruchamia monitorowanie USB w osobnym wątku i startuje GUI.
    def run(self):
        known_drives = USBUtility.list_all_drives()
        threading.Thread(target=self.monitor_usb, args=(known_drives,), daemon=True).start()
        self.gui.mainloop()