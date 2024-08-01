import tkinter as tk
from tkinter import simpledialog, messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import pyperclip


# AES encryption
def aes_encrypt(plain_text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_text = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    return base64.b64encode(iv + encrypted_text).decode('utf-8')


# AES decryption
def add_padding(base64_string):
    return base64_string + '=' * (-len(base64_string) % 4)


def aes_decrypt(encrypted_text, key):
    encrypted_text = add_padding(encrypted_text)
    encrypted_data = base64.b64decode(encrypted_text)
    iv = encrypted_data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_text = unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size)
    return decrypted_text.decode('utf-8')


# Function to copy text to clipboard
def copy_to_clipboard(text):
    pyperclip.copy(text)
    messagebox.showinfo("Copy to Clipboard", "Text copied to clipboard!")


# GUI application
class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Encryption/Decryption")
        self.root.configure(bg='black')
        self.root.geometry("500x400")

        self.key = get_random_bytes(16)  # AES key (must be kept secret)
        self.key_str = base64.b64encode(self.key).decode('utf-8')

        # Title Label
        self.title_label = tk.Label(root, text="AES Base 64", fg='green', bg='black', font=("Courier", 18))
        self.title_label.pack(pady=10)

        # Encoding UI
        self.encode_frame = tk.Frame(root, bg='black')
        self.encode_label = tk.Label(self.encode_frame, text="Message to Encode:", fg='white', bg='black',
                                     font=("Courier", 12))
        self.encode_label.pack(anchor='w')
        self.encode_entry = tk.Entry(self.encode_frame, width=50, bg='black', fg='green', insertbackground='green',
                                     font=("Courier", 12))
        self.encode_entry.pack(pady=5)
        self.encode_button = tk.Button(self.encode_frame, text="Encode", command=self.encode_message, bg='black',
                                       fg='green', font=("Courier", 12), relief='ridge', borderwidth=3)
        self.encode_button.pack()
        self.encode_frame.pack(pady=10)

        # Decoding UI
        self.decode_frame = tk.Frame(root, bg='black')
        self.decode_label = tk.Label(self.decode_frame, text="Message to Decode:", fg='white', bg='black',
                                     font=("Courier", 12))
        self.decode_label.pack(anchor='w')
        self.decode_entry = tk.Entry(self.decode_frame, width=50, bg='black', fg='green', insertbackground='green',
                                     font=("Courier", 12))
        self.decode_entry.pack(pady=5)
        self.decode_button = tk.Button(self.decode_frame, text="Decode", command=self.decode_message, bg='black',
                                       fg='green', font=("Courier", 12), relief='ridge', borderwidth=3)
        self.decode_button.pack()
        self.decode_frame.pack(pady=10)

        # Key management UI
        self.pin_button = tk.Button(root, text="Enter PIN to Show/Change Key", command=self.enter_pin, bg='black',
                                    fg='green', font=("Courier", 12), relief='ridge', borderwidth=3)
        self.pin_button.pack(pady=20)

    def encode_message(self):
        plain_text = self.encode_entry.get()
        encrypted_message = aes_encrypt(plain_text, self.key)
        self.show_message_box("Encoded Message", encrypted_message)
        self.encode_entry.delete(0, tk.END)

    def decode_message(self):
        encrypted_text = self.decode_entry.get()
        try:
            decrypted_message = aes_decrypt(encrypted_text, self.key)
            self.show_message_box("Decoded Message", decrypted_message)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decode message: {e}")
        self.decode_entry.delete(0, tk.END)

    def show_message_box(self, title, message):
        msg_box = tk.Toplevel(self.root)
        msg_box.title(title)
        msg_box.configure(bg='black')
        tk.Label(msg_box, text=message, wraplength=400, fg='green', bg='black', font=("Courier", 12)).pack(padx=10,
                                                                                                           pady=10)
        copy_button = tk.Button(msg_box, text="Copy to Clipboard", command=lambda: copy_to_clipboard(message),
                                bg='black', fg='green', font=("Courier", 12), relief='ridge', borderwidth=3)
        copy_button.pack(pady=5)
        close_button = tk.Button(msg_box, text="Close", command=msg_box.destroy, bg='black', fg='green',
                                 font=("Courier", 12), relief='ridge', borderwidth=3)
        close_button.pack(pady=5)

    def enter_pin(self):
        pin = simpledialog.askstring("PIN Entry", "Enter PIN:", show='*')
        if pin == "780302":  # Example PIN, replace with secure method for production
            self.show_key_management()
        else:
            messagebox.showerror("Error", "Incorrect PIN!")

    def show_key_management(self):
        key_box = tk.Toplevel(self.root)
        key_box.title("Key Management")
        key_box.configure(bg='black')

        key_label = tk.Label(key_box, text=f"Current Key: {self.key_str}", fg='green', bg='black', font=("Courier", 12))
        key_label.pack(padx=10, pady=10)

        new_key_label = tk.Label(key_box, text="Enter New Key (Base64):", fg='white', bg='black', font=("Courier", 12))
        new_key_label.pack()
        self.new_key_entry = tk.Entry(key_box, width=50, bg='black', fg='green', insertbackground='green',
                                      font=("Courier", 12))
        self.new_key_entry.pack()

        change_key_button = tk.Button(key_box, text="Change Key", command=self.change_key, bg='black', fg='green',
                                      font=("Courier", 12), relief='ridge', borderwidth=3)
        change_key_button.pack(pady=5)
        close_button = tk.Button(key_box, text="Close", command=key_box.destroy, bg='black', fg='green',
                                 font=("Courier", 12), relief='ridge', borderwidth=3)
        close_button.pack(pady=5)

    def change_key(self):
        new_key_str = self.new_key_entry.get()
        try:
            new_key = base64.b64decode(new_key_str)
            if len(new_key) not in [16, 24, 32]:
                raise ValueError("Invalid key length")
            self.key = new_key
            self.key_str = new_key_str
            messagebox.showinfo("Success", "Key changed successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to change key: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
