import tkinter as tk
from tkinter import ttk, messagebox

from key_generator import KeyGenerator


class GUI:

    def __init__(self):
        self.key_generator = KeyGenerator()
        self.root = self.__create_root_window()
        self.frame = self.__create_frame(self.root)
        self.__create_pin_input_widget(self.frame)

    def __create_root_window(self):
        root = tk.Tk()
        root.title("Secure RSA Key Generator")
        root.geometry("400x250")
        root.resizable(False, False)

        return root


    def __create_frame(self, root):
        style = ttk.Style()
        style.configure("TButton", font=("Segoe UI", 10), padding=6)
        style.configure("TLabel", font=("Segoe UI", 10))

        frame = ttk.Frame(root, padding=20)
        frame.pack(fill="both", expand=True)

        footer = ttk.Label(frame, text="RSA-4096 | AES-256 | SHA-256", font=("Segoe UI", 9, "italic"),
                           foreground="gray")
        footer.pack(side="bottom", pady=(20, 0))

        return frame

    def __create_pin_input_widget(self, frame):
        ttk.Label(frame, text="Enter your secure PIN:").pack(pady=(0, 5))

        pin_var = tk.StringVar()
        pin_entry = ttk.Entry(frame, textvariable=pin_var, show="*", width=30)
        pin_entry.pack(pady=(0, 15))

        generate_btn = ttk.Button(frame, text="Generate & Save Keys",
                                  command=lambda: self.__get_pin_and_generate_key(pin_var))
        generate_btn.pack(pady=(0, 10))

    def __get_pin_and_generate_key(self, pin_var):
        pin = pin_var.get()
        if not pin:
            messagebox.showerror("Missing PIN", "Please enter a PIN code.")
            return
        self.key_generator.generate_keys(pin)

    def display_main_menu(self):
        self.root.mainloop()