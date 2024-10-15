from Crypto.Cipher import AES, DES, DES3, Blowfish
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os

BLOCK_SIZE = 16

# Padding and Unpadding Functions
def pad(text, block_size):
    padding_length = block_size - len(text) % block_size
    return text + (chr(padding_length) * padding_length)

def unpad(text):
    padding_length = ord(text[-1])
    return text[:-padding_length]

# Encryption Function
def encrypt(plain_text, key, algorithm):
    try:
        if algorithm == 'AES':
            cipher = AES.new(key, AES.MODE_ECB)
            padded_text = pad(plain_text, BLOCK_SIZE)
            encrypted_bytes = cipher.encrypt(padded_text.encode('utf-8'))
            return b64encode(encrypted_bytes).decode('utf-8')
        elif algorithm == 'DES':
            if len(key) != 8:
                raise ValueError("DES key must be 8 bytes long")
            cipher = DES.new(key, DES.MODE_ECB)
            padded_text = pad(plain_text, DES.block_size)
            encrypted_bytes = cipher.encrypt(padded_text.encode('utf-8'))
            return b64encode(encrypted_bytes).decode('utf-8')
        elif algorithm == '3DES':
            if len(key) != 16 and len(key) != 24:
                raise ValueError("3DES key must be either 16 or 24 bytes long")
            cipher = DES3.new(key, DES3.MODE_ECB)
            padded_text = pad(plain_text, DES3.block_size)
            encrypted_bytes = cipher.encrypt(padded_text.encode('utf-8'))
            return b64encode(encrypted_bytes).decode('utf-8')
        elif algorithm == 'Blowfish':
            cipher = Blowfish.new(key, Blowfish.MODE_ECB)
            padded_text = pad(plain_text, Blowfish.block_size)
            encrypted_bytes = cipher.encrypt(padded_text.encode('utf-8'))
            return b64encode(encrypted_bytes).decode('utf-8')
        elif algorithm == 'Rijndael':
            cipher = AES.new(key, AES.MODE_ECB)
            padded_text = pad(plain_text, BLOCK_SIZE)
            encrypted_bytes = cipher.encrypt(padded_text.encode('utf-8'))
            return b64encode(encrypted_bytes).decode('utf-8')
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {str(e)}")
        return None

# Decryption Function
def decrypt(cipher_text, key, algorithm):
    try:
        decoded_data = b64decode(cipher_text)
        if algorithm == 'AES':
            cipher = AES.new(key, AES.MODE_ECB)
            decrypted_text = unpad(cipher.decrypt(decoded_data).decode('utf-8'))
            return decrypted_text
        elif algorithm == 'DES':
            cipher = DES.new(key, DES.MODE_ECB)
            decrypted_text = unpad(cipher.decrypt(decoded_data).decode('utf-8'))
            return decrypted_text
        elif algorithm == '3DES':
            cipher = DES3.new(key, DES3.MODE_ECB)
            decrypted_text = unpad(cipher.decrypt(decoded_data).decode('utf-8'))
            return decrypted_text
        elif algorithm == 'Blowfish':
            cipher = Blowfish.new(key, Blowfish.MODE_ECB)
            decrypted_text = unpad(cipher.decrypt(decoded_data).decode('utf-8'))
            return decrypted_text
        elif algorithm == 'Rijndael':
            cipher = AES.new(key, AES.MODE_ECB)
            decrypted_text = unpad(cipher.decrypt(decoded_data).decode('utf-8'))
            return decrypted_text
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")
        return None

# Key generation function
def generate_key(algorithm):
    if algorithm == 'AES':
        return get_random_bytes(32)  # AES uses 16, 24, or 32 bytes
    elif algorithm == 'DES':
        return get_random_bytes(8)  # DES uses 8-byte (64-bit) key
    elif algorithm == '3DES':
        return get_random_bytes(24)  # 24-byte key for 3DES
    elif algorithm == 'Blowfish':
        return get_random_bytes(16)  # Blowfish key can be between 4-56 bytes, 16 is typical
    elif algorithm == 'Rijndael':
        return get_random_bytes(32)  # Rijndael with 32 bytes for AES-256 equivalent
    else:
        return None

# Function to open and read a file
def open_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, 'r') as file:
            text_input.delete("1.0", tk.END)
            text_input.insert(tk.END, file.read())
        messagebox.showinfo("Success", "File uploaded successfully!")

# Function to save the result to a file
def save_file(result_text):
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, 'w') as file:
            file.write(result_text)
        messagebox.showinfo("Success", "File saved successfully!")

# Function to handle text encryption/decryption
def process_text(action):
    plain_text = text_input.get("1.0", tk.END).strip()  # Now defined correctly
    key = get_key()
    algorithm = algorithm_choice.get()

    if plain_text and key:
        if action == 'encrypt':
            result = encrypt(plain_text, key, algorithm)
        elif action == 'decrypt':
            result = decrypt(plain_text, key, algorithm)
        if result:
            result_output.delete("1.0", tk.END)
            result_output.insert(tk.END, result)
            save_file(result)

# Function to generate and display a new key
def generate_new_key():
    key = generate_key(algorithm_choice.get())
    key_display.delete(0, tk.END)
    key_display.insert(0, b64encode(key).decode('utf-8'))

# Function to get the key from input field
def get_key():
    key_input = key_display.get().strip()
    if len(key_input) == 0:
        messagebox.showwarning("Warning", "Key is missing! Either enter a key or generate one.")
        return None
    try:
        return b64decode(key_input)
    except Exception as e:
        messagebox.showerror("Error", f"Invalid key: {str(e)}")
        return None

# Function to reset fields
def reset_fields():
    text_input.delete("1.0", tk.END)
    key_display.delete(0, tk.END)
    result_output.delete("1.0", tk.END)

# Main application function
def create_app():
    root = tk.Tk()
    root.title("Encryption & Decryption")
    root.geometry("600x500")  # Set a default size for the window
    root.configure(bg='#f0f0f0')

    # Notebook (Tabs) for encryption and decryption
    notebook = ttk.Notebook(root)
    notebook.pack(fill='both', expand=True)

    # Encryption Page
    encryption_frame = ttk.Frame(notebook, padding=10)
    notebook.add(encryption_frame, text="Encrypt")

    # Encryption page content
    tk.Label(encryption_frame, text="Encryption", font=("Arial", 16), background='#2C2C2C',fg='#FFFFFF').pack(pady=10)
    tk.Label(encryption_frame, text="Select Algorithm:", background='#f0f0f0').pack(pady=5)
    global algorithm_choice
    algorithm_choice = ttk.Combobox(encryption_frame, values=["AES", "DES", "3DES", "Blowfish", "Rijndael"])
    algorithm_choice.current(0)
    algorithm_choice.pack(pady=5)

    tk.Button(encryption_frame, text="Upload File", command=open_file,bg='#33FF57').pack(pady=5)

    tk.Label(encryption_frame, text="Enter or Generate Key:", background='#f0f0f0').pack(pady=5)
    global key_display
    key_display = tk.Entry(encryption_frame, width=50)
    key_display.pack(pady=5)
    tk.Button(encryption_frame, text="Generate New Key", command=generate_new_key,bg='#3380FF',fg='#FFFFFF').pack(pady=5)

    global text_input  # Now defined correctly
    tk.Label(encryption_frame, text="Enter Text to Encrypt:", background='#f0f0f0').pack(pady=5)
    text_input = tk.Text(encryption_frame, height=5, width=50)
    text_input.pack(pady=5)

    tk.Button(encryption_frame, text="Encrypt", command=lambda: process_text('encrypt'),bg='#FF5733').pack(pady=5)
    tk.Button(encryption_frame, text="Reset", command=reset_fields).pack(pady=5)

    global result_output
    tk.Label(encryption_frame, text="Result:", background='#f0f0f0').pack(pady=5)
    result_output = tk.Text(encryption_frame, height=5, width=50)
    result_output.pack(pady=5)

    # Decryption Page
    decryption_frame = ttk.Frame(notebook, padding=10)
    notebook.add(decryption_frame, text="Decrypt")

    tk.Button(decryption_frame, text="Upload File", command=open_file,bg='#33FF57').pack(pady=5)
    tk.Button(decryption_frame, text="Decrypt", command=lambda: process_text('decrypt'),bg='#FF5733').pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    create_app()
