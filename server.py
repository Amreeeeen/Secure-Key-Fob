import socket
import pickle
from ecdh_util import generate_ecdh_key_pair, derive_shared_secret
from hash_util import sha256_hash
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os
import subprocess

# Load whitelist of authorized fob public keys (in PEM format)
with open("whitelist.pkl", "rb") as f:
    whitelist = pickle.load(f)

HOST = 'localhost'
PORT = 9999

print("🚘 Car ECU is waiting for key fob connection...")

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(1)

conn, addr = server.accept()
print(f"📡 Connected by {addr}")

# --- Generate car key pair ---
car_private, car_public = generate_ecdh_key_pair()

# Send public key to fob
car_pub_pem = car_public.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
conn.send(car_pub_pem)
print("📤 Sent car's public key")

# --- Receive fob's public key (PEM format) ---
fob_pub_pem = conn.recv(4096)
print("📥 Received fob's public key")

# --- Check if authorized ---
if fob_pub_pem not in whitelist:
    print("🚫 Unauthorized fob! Access denied.")
    os.system("say 'Unauthorized fob detected!'")
    subprocess.run([
        "osascript", "-e",
        'display alert "SECURITY BREACH" message "An unauthorized fob tried to connect."'
    ])
    conn.close()
    exit()

print("✅ Authorized fob detected.")

# Convert fob public key PEM to object
fob_public = serialization.load_pem_public_key(fob_pub_pem, backend=default_backend())

# Derive shared secret
shared_key = derive_shared_secret(car_private, fob_public)

# Generate a challenge
challenge = os.urandom(16)
conn.send(challenge)

# Receive response
response = conn.recv(1024)

# Verify hash
expected_hash, _ = sha256_hash(challenge)
if response.decode() == expected_hash:
    print("✅ Challenge verified. Access granted.")
else:
    print("❌ Challenge failed. Possible tampering detected.")
    os.system("say 'Challenge failed. Tampering suspected.'")
    subprocess.run([
        "osascript", "-e",
        'display alert "TAMPER WARNING" message "Response hash didn’t match challenge."'
    ])

conn.close()
