## @file utils.py
#  @brief Zawiera klasy pomocnicze do obsługi USB, generowania i szyfrowania kluczy RSA oraz podpisywania danych.
from Cryptodome.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import rsa
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import win32api
import os
import time
## @class USBUtility
#  @brief Zbiór metod pomocniczych do obsługi pamięci USB.
class USBUtility:
    ## @brief Zwraca zestaw wszystkich aktualnie podłączonych napędów logicznych.
    @staticmethod
    @staticmethod
    def list_all_drives():
        return set(win32api.GetLogicalDriveStrings().split('\x00')[:-1])

    ## @brief Zapisuje bajty do pliku.
    #  @param path Ścieżka do pliku.
    #  @param content_bytes Zawartość bajtowa do zapisania.
    @staticmethod
    def write_file(path, content_bytes):
        with open(path, "wb") as f:
            f.write(content_bytes)
## @class RSAKeyHandler
#  @brief Klasa generująca i eksportująca pary kluczy RSA.
class RSAKeyHandler:
    ## @brief Inicjalizuje parę kluczy RSA 4096-bitowych.
    def __init__(self):
        self.key_pair = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    ## @brief Eksportuje klucz publiczny w formacie PEM.
    #  @return Klucz publiczny jako bajty.
    def export_public_key(self):
        pub_bytes = self.key_pair.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pub_bytes

    ## @brief Eksportuje klucz prywatny w formacie PEM (bez szyfrowania).
    #  @return Klucz prywatny jako bajty.
    def export_private_key(self):
        return self.key_pair.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())
## @class KeySecurity
#  @brief Obsługuje szyfrowanie klucza prywatnego przy pomocy PIN-u.
class KeySecurity:
    ## @brief Wyprowadza klucz AES z podanego PIN-u.
    #  @param pin Kod PIN jako string.
    #  @return Klucz AES (32 bajty)
    @staticmethod
    def derive_key_from_pin(pin):
        return SHA256.new(pin.encode()).digest()

    ## @brief Szyfruje dane klucza prywatnego przy użyciu AES-CFB.
    #  @param private_data Dane do zaszyfrowania (klucz prywatny).
    #  @param pin Kod PIN jako string.
    #  @return IV + zaszyfrowane dane.
    @staticmethod
    def encrypt_private_data(private_data, pin):
        iv = get_random_bytes(16)
        key = KeySecurity.derive_key_from_pin(pin)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        return iv + cipher.encrypt(private_data)

## @class DriveWatcher
#  @brief Monitoruje podłączone dyski i sprawdza, czy zawierają dany plik.
class DriveWatcher:
    ## @brief Konstruktor klasy.
    #  @param target_filename Nazwa pliku, którego szukamy.
    def __init__(self, target_filename):
        self.filename = target_filename

    ## @brief Czeka, aż plik pojawi się na którymkolwiek z dysków.
    #  @return Pełna ścieżka do odnalezionego pliku.
    def wait_for_media(self):
        while True:
            drives = win32api.GetLogicalDriveStrings().split('\x00')[:-1]
            for disk in drives:
                candidate = os.path.join(disk, self.filename)
                if os.path.isfile(candidate):
                    return candidate
            time.sleep(1.5)
## @class KeyDecryptor
#  @brief Deszyfruje klucz prywatny zaszyfrowany przy pomocy PIN-u.
class KeyDecryptor:
    ## @brief Konstruktor klasy.
    #  @param encrypted_bytes Dane zaszyfrowane (IV + ciphertext).
    #  @param pin_code Kod PIN jako string.
    def __init__(self, encrypted_bytes, pin_code):
        self.data = encrypted_bytes
        self.pin = pin_code

    ## @brief Odszyfrowuje dane i zwraca klucz RSA.
    #  @return Odszyfrowany klucz prywatny RSA.
    def get_private_key(self):
        iv_part = self.data[:16]
        encrypted_part = self.data[16:]
        key_material = SHA256.new(self.pin.encode()).digest()
        cipher = AES.new(key_material, AES.MODE_CFB, iv_part)
        decrypted = cipher.decrypt(encrypted_part)
        return serialization.load_pem_private_key(decrypted, password=None)
## @class DigitalSigner
#  @brief Obsługuje podpisywanie danych za pomocą klucza RSA.
class DigitalSigner:
    ## @brief Konstruktor klasy.
    #  @param rsa_key Klucz RSA (prywatny).
    def __init__(self, rsa_key):
        self.key = rsa_key

    ## @brief Tworzy podpis cyfrowy dla przekazanych danych.
    #  @param raw_bytes Surowe dane do podpisania.
    #  @return Podpis cyfrowy (bajty).
    def sign_data(self, raw_bytes):
        doc_hash = SHA256.new(raw_bytes).digest()
        return self.key.sign(doc_hash, padding.PKCS1v15(), hashes.SHA256())