# decryptor.py
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from pathlib import Path
import os
import sys

# Load private RSA key
def load_private_key():
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.abspath(".")
        
    key_path = os.path.join(base_path, "RSA_private.pem")
    with open(key_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

# AES decryption
def aes_decrypt(encrypted_data, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

# Decrypt file
def decrypt_file(filepath, private_key):
    try:
        with open(filepath, "rb") as f:
            content = f.read()
        iv, encrypted_key, encrypted_data = content.split(b":::", 2)

        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        data = aes_decrypt(encrypted_data, aes_key, iv)
        restored_path = filepath.replace(".locked", "")
        with open(restored_path, "wb") as f:
            f.write(data)

        os.remove(filepath)
        print(f"[✓] Decrypted: {restored_path}")
    except Exception as e:
        print(f"[X] Failed to decrypt {filepath}: {e}")

# Duyệt file
def get_locked_files(folder):
    return [str(p) for p in Path(folder).rglob("*") if str(p).endswith(".locked")]

# MAIN
if __name__ == "__main__":
    key = load_private_key()
    folder = os.path.expanduser("~/Documents")
    for path in get_locked_files(folder):
        decrypt_file(path, key)
    print("\n[✓] All files recovered.")
