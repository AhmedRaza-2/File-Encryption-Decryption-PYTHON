import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from Crypto.Cipher import AES, DES, DES3, Blowfish, ChaCha20, ARC4, CAST
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class Encryptor:
    def __init__(self, algorithm):
        self.algorithm = algorithm

    def generate_key(self):
        if self.algorithm == 'AES':
            return get_random_bytes(32)  # 256-bit key
        elif self.algorithm == 'DES':
            return get_random_bytes(8)  # 64-bit key
        elif self.algorithm == '3DES':
            return get_random_bytes(24)  # 192-bit key
        elif self.algorithm == 'Blowfish':
            return get_random_bytes(16)  # 128-bit key
        elif self.algorithm == 'ChaCha20':
            return get_random_bytes(32)  # 256-bit key
        elif self.algorithm == 'RC4':
            return get_random_bytes(16)  # 128-bit key
        elif self.algorithm == 'CAST':
            return get_random_bytes(16)  # 128-bit key

    def file_encrypt(self, key, original_file, encrypted_file):
        if self.algorithm == 'AES':
            cipher = AES.new(key, AES.MODE_EAX)
        elif self.algorithm == 'DES':
            cipher = DES.new(key, DES.MODE_EAX)
        elif self.algorithm == '3DES':
            cipher = DES3.new(key, DES3.MODE_EAX)
        elif self.algorithm == 'Blowfish':
            cipher = Blowfish.new(key, Blowfish.MODE_EAX)
        elif self.algorithm == 'ChaCha20':
            cipher = ChaCha20.new(key=key)
        elif self.algorithm == 'RC4':
            cipher = ARC4.new(key)
        elif self.algorithm == 'CAST':
            cipher = CAST.new(key, CAST.MODE_EAX)

        with open(original_file, 'rb') as file:
            original = file.read()

        if self.algorithm in ['AES', 'DES', '3DES', 'Blowfish', 'CAST']:
            original = pad(original, cipher.block_size)
            ciphertext, tag = cipher.encrypt_and_digest(original)
            with open(encrypted_file, 'wb') as file:
                file.write(cipher.nonce)
                file.write(tag)
                file.write(ciphertext)
        elif self.algorithm == 'ChaCha20':
            ciphertext = cipher.encrypt(original)
            with open(encrypted_file, 'wb') as file:
                file.write(cipher.nonce)
                file.write(ciphertext)
        elif self.algorithm == 'RC4':
            ciphertext = cipher.encrypt(original)
            with open(encrypted_file, 'wb') as file:
                file.write(ciphertext)

    def file_decrypt(self, key, encrypted_file, decrypted_file):
     with open(encrypted_file, 'rb') as file:
        if self.algorithm in ['AES', 'DES', '3DES', 'Blowfish', 'CAST']:
            # Read nonce and tag before reading the ciphertext
            nonce = file.read(16)  # Nonce is usually 16 bytes for EAX mode
            tag = file.read(16)  # Tag is usually 16 bytes
            ciphertext = file.read()

            if self.algorithm == 'AES':
                cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            elif self.algorithm == 'DES':
                cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)
            elif self.algorithm == '3DES':
                cipher = DES3.new(key, DES3.MODE_EAX, nonce=nonce)
            elif self.algorithm == 'Blowfish':
                cipher = Blowfish.new(key, Blowfish.MODE_EAX, nonce=nonce)
            elif self.algorithm == 'CAST':
                cipher = CAST.new(key, CAST.MODE_EAX, nonce=nonce)

            try:
                decrypted = cipher.decrypt_and_verify(ciphertext, tag)
                decrypted = unpad(decrypted, cipher.block_size)
            except ValueError as e:
                messagebox.showerror("Error", f"Decryption failed: {str(e)}")
                return
        elif self.algorithm == 'ChaCha20':
            nonce = file.read(12)  # Nonce for ChaCha20 is usually 12 bytes
            ciphertext = file.read()
            cipher = ChaCha20.new(key=key, nonce=nonce)
            decrypted = cipher.decrypt(ciphertext)
        elif self.algorithm == 'RC4':
            ciphertext = file.read()
            cipher = ARC4.new(key)
            decrypted = cipher.decrypt(ciphertext)
        else:
            messagebox.showerror("Error", "Unsupported algorithm")
            return

     with open(decrypted_file, 'wb') as file:
        file.write(decrypted)

class EncryptorGUI:
    def __init__(self, master):
        self.master = master
        master.title("File Encryptor/Decryptor")
        master.geometry("600x600")
        master.configure(bg="#34495e")
        self.key = None

        style = ttk.Style()
        style.configure("TLabel", background="#34495e", foreground="#ecf0f1", font=("Helvetica", 10))
        style.configure("TButton", background="#1abc9c", foreground="#2c3e50", font=("Helvetica", 10, "bold"), padding=6)
        style.configure("TCombobox", font=("Helvetica", 10))
        style.configure("TEntry", font=("Helvetica", 10))

        self.title_label = ttk.Label(master, text="File Encryptor/Decryptor", font=("Helvetica", 14, "bold"), background="#34495e", foreground="#1abc9c")
        self.title_label.pack(pady=15)

        self.algorithm_label = ttk.Label(master, text="Select Encryption Algorithm:")
        self.algorithm_label.pack(pady=5)
        self.algorithm_var = tk.StringVar()
        self.algorithm_dropdown = ttk.Combobox(master, textvariable=self.algorithm_var, values=['AES', 'DES', '3DES', 'Blowfish', 'ChaCha20', 'RC4', 'CAST'], state="readonly")
        self.algorithm_dropdown.current(0)
        self.algorithm_dropdown.pack(pady=5)

        self.key_frame = ttk.LabelFrame(master, text="Key Management", style="TLabelframe", padding=(10, 5))
        self.key_frame.pack(fill="x", padx=15, pady=10)

        self.key_create_button = ttk.Button(self.key_frame, text="Create Key", command=self.create_key)
        self.key_create_button.grid(row=0, column=0, padx=5, pady=5)

        self.key_load_button = ttk.Button(self.key_frame, text="Load Key", command=self.load_key)
        self.key_load_button.grid(row=0, column=1, padx=5, pady=5)

        self.file_frame = ttk.LabelFrame(master, text="File Selection", style="TLabelframe", padding=(10, 5))
        self.file_frame.pack(fill="x", padx=15, pady=10)

        self.original_file_label = ttk.Label(self.file_frame, text="Original File:")
        self.original_file_label.grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.original_file_entry = ttk.Entry(self.file_frame, width=35)
        self.original_file_entry.grid(row=0, column=1, padx=5, pady=5)
        self.original_file_button = ttk.Button(self.file_frame, text="Browse", command=self.select_original_file)
        self.original_file_button.grid(row=0, column=2, padx=5, pady=5)

        self.encrypted_file_label = ttk.Label(self.file_frame, text="Encrypted/Decrypted File:")
        self.encrypted_file_label.grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.encrypted_file_entry = ttk.Entry(self.file_frame, width=35)
        self.encrypted_file_entry.grid(row=1, column=1, padx=5, pady=5)
        self.encrypted_file_button = ttk.Button(self.file_frame, text="Browse", command=self.select_encrypted_file)
        self.encrypted_file_button.grid(row=1, column=2, padx=5, pady=5)

        self.action_frame = ttk.LabelFrame(master, text="Actions", style="TLabelframe", padding=(10, 5))
        self.action_frame.pack(fill="x", padx=15, pady=10)

        self.encrypt_button = ttk.Button(self.action_frame, text="Encrypt", command=self.encrypt)
        self.encrypt_button.grid(row=0, column=0, padx=10, pady=5)

        self.decrypt_button = ttk.Button(self.action_frame, text="Decrypt", command=self.decrypt)
        self.decrypt_button.grid(row=0, column=1, padx=10, pady=5)

        self.exit_button = ttk.Button(self.action_frame, text="Exit", command=master.quit)
        self.exit_button.grid(row=0, column=2, padx=10, pady=5)

        self.result_text = tk.Text(master, height=10, width=60, wrap="word", bg="#ecf0f1", fg="#2c3e50", font=("Helvetica", 10))
        self.result_text.pack(padx=15, pady=10)

    def create_key(self):
        algorithm = self.algorithm_var.get()
        encryptor = Encryptor(algorithm)
        key = encryptor.generate_key()

        key_file = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key Files", "*.key")])
        if key_file:
            with open(key_file, 'wb') as file:
                file.write(key)
            self.result_text.insert(tk.END, f"Key generated and saved to: {key_file}\n")
            self.key = key

    def load_key(self):
        key_file = filedialog.askopenfilename(filetypes=[("Key Files", "*.key")])
        if key_file:
            with open(key_file, 'rb') as file:
                self.key = file.read()
            self.result_text.insert(tk.END, f"Key loaded from: {key_file}\n")

    def select_original_file(self):
        original_file = filedialog.askopenfilename()
        if original_file:
            self.original_file_entry.delete(0, tk.END)
            self.original_file_entry.insert(0, original_file)

    def select_encrypted_file(self):
        encrypted_file = filedialog.asksaveasfilename()
        if encrypted_file:
            self.encrypted_file_entry.delete(0, tk.END)
            self.encrypted_file_entry.insert(0, encrypted_file)

    def encrypt(self):
        algorithm = self.algorithm_var.get()
        original_file = self.original_file_entry.get()
        encrypted_file = self.encrypted_file_entry.get()

        if not self.key:
            messagebox.showerror("Error", "No key loaded or created.")
            return

        encryptor = Encryptor(algorithm)
        try:
            encryptor.file_encrypt(self.key, original_file, encrypted_file)
            self.result_text.insert(tk.END, f"File encrypted and saved to: {encrypted_file}\n")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt(self):
     algorithm = self.algorithm_var.get()
     encrypted_file = self.original_file_entry.get()  # Using the original file entry as the encrypted file path
     decrypted_file = self.encrypted_file_entry.get()  # Using the encrypted file entry as the decrypted file path

     if not self.key:
        messagebox.showerror("Error", "No key loaded or created.")
        return

     encryptor = Encryptor(algorithm)
     try:
        encryptor.file_decrypt(self.key, encrypted_file, decrypted_file)
        self.result_text.insert(tk.END, f"File decrypted and saved to: {decrypted_file}\n")
     except Exception as e:
        messagebox.showerror("Error", f"Decryption Done")
if __name__ == "__main__":
    root = tk.Tk()
    gui = EncryptorGUI(root)
    root.mainloop()
