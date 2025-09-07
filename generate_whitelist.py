from ecdh_util import generate_ecdh_key_pair
from cryptography.hazmat.primitives import serialization
import pickle

whitelist = []

for i in range(3):  # Create 3 valid fobs
    priv, pub = generate_ecdh_key_pair()

    # Convert public key to PEM (standard format)
    pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    whitelist.append(pem)

# Save to file
with open("whitelist.pkl", "wb") as f:
    pickle.dump(whitelist, f)

print("✅ Whitelist created with 3 authorized fobs.")
