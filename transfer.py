"""
Secure File Transfer Module
Uses AES encryption + SFTP simulation for secure file transfer
"""

import os
import hashlib
import logging
from datetime import datetime
from cryptography.fernet import Fernet

# Setup logging
logging.basicConfig(
    filename="logs/transfer.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def generate_key():
    """Generate and save encryption key"""
    key = Fernet.generate_key()
    with open("secret.key", "wb") as f:
        f.write(key)
    print("[✔] Encryption key generated: secret.key")
    return key

def load_key():
    """Load existing encryption key"""
    if not os.path.exists("secret.key"):
        return generate_key()
    with open("secret.key", "rb") as f:
        return f.read()

def encrypt_file(filepath):
    """Encrypt a file using AES (Fernet)"""
    key = load_key()
    fernet = Fernet(key)

    with open(filepath, "rb") as f:
        original = f.read()

    encrypted = fernet.encrypt(original)
    enc_path = filepath + ".enc"

    with open(enc_path, "wb") as f:
        f.write(encrypted)

    print(f"[✔] File encrypted: {enc_path}")
    logging.info(f"ENCRYPTED | file={filepath}")
    return enc_path

def decrypt_file(enc_filepath):
    """Decrypt an encrypted file"""
    key = load_key()
    fernet = Fernet(key)

    with open(enc_filepath, "rb") as f:
        encrypted = f.read()

    decrypted = fernet.decrypt(encrypted)
    out_path = enc_filepath.replace(".enc", ".decrypted")

    with open(out_path, "wb") as f:
        f.write(decrypted)

    print(f"[✔] File decrypted: {out_path}")
    logging.info(f"DECRYPTED | file={enc_filepath}")
    return out_path

def get_file_hash(filepath):
    """Get SHA-256 hash of file for integrity check"""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def simulate_transfer(src_file, src_ip="192.168.1.10", dst_ip="192.168.1.20"):
    """Simulate a secure file transfer"""
    print(f"\n{'='*50}")
    print(f"[→] Initiating Secure Transfer")
    print(f"    From : {src_ip}")
    print(f"    To   : {dst_ip}")
    print(f"    File : {src_file}")
    print(f"{'='*50}")

    if not os.path.exists(src_file):
        print(f"[✘] File not found: {src_file}")
        return False

    # Get file hash before transfer
    original_hash = get_file_hash(src_file)
    file_size = os.path.getsize(src_file)
    print(f"[i] File Size : {file_size} bytes")
    print(f"[i] SHA-256   : {original_hash[:30]}...")

    # Encrypt file
    enc_file = encrypt_file(src_file)

    # Simulate transfer (copy to received/ folder)
    os.makedirs("received", exist_ok=True)
    received_path = os.path.join("received", os.path.basename(enc_file))
    with open(enc_file, "rb") as src, open(received_path, "wb") as dst:
        dst.write(src.read())

    print(f"[✔] Transfer Complete → {received_path}")

    # Log to database
    from monitor import log_to_db
    log_to_db(src_ip, dst_ip, src_file, file_size, original_hash, "SUCCESS")

    # Check for anomaly
    from monitor import check_anomaly
    alert = check_anomaly(file_size, src_ip)
    if alert:
        from alerts import send_console_alert
        send_console_alert(alert)

    return received_path
