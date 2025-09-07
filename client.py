import socket
import os
import pickle
from ecdh_util import generate_ecdh_key_pair, derive_shared_secret
from hash_util import sha256_hash
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

HOST = 'localhost'
PORT = 9999

print("🚀 Script started...")
print("🔐 Key Fob: Connecting to car ECU...")

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))
print("✅ Connected to server.")

# --- Load or generate key pair ---
if os.path.exists("fob_private.pem") and os.path.exists("fob_public.pem"):
    with open("fob_private.pem", "rb") as f:
        fob_private = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    with open("fob_public.pem", "rb") as f:
        fob_public = serialization.load_pem_public_key(f.read(), backend=default_backend())
else:
    fob_private, fob_public = generate_ecdh_key_pair()
    with open("fob_private.pem", "wb") as f:
        f.write(fob_private.private_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm = serialization.NoEncryption()
        ))
    with open("fob_public.pem", "wb") as f:
        f.write(fob_public.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# --- Receive car's public key ---
car_pub_pem = client.recv(4096)
print("✅ Received car's public key")

car_public = serialization.load_pem_public_key(car_pub_pem, backend=default_backend())

# --- Send fob's public key ---
fob_pub_pem = fob_public.public_bytes(
    encoding = serialization.Encoding.PEM,
    format = serialization.PublicFormat.SubjectPublicKeyInfo
)
print("🧾 Fob public key PEM hash:", sha256_hash(fob_pub_pem)[0])
client.send(fob_pub_pem)
print("📤 Sent fob's public key")

# --- Receive challenge ---
challenge = client.recv(1024)
if not challenge:
    print("❌ No challenge received. Connection might be closed.")
    client.close()
    exit()

# --- Simulate tampering if needed ---
tamper = True
if tamper:
    print("⚠️  Simulating tampered challenge...")
    challenge = bytearray(challenge)
    if len(challenge) > 0:
        challenge[0] ^= 0xFF
    challenge = bytes(challenge)

# --- Hash and send response ---
hashed, _ = sha256_hash(challenge)
client.send(hashed.encode())
print("📡 Response sent. Waiting for verification...")

client.close()
