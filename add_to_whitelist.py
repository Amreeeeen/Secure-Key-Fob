import pickle
from cryptography.hazmat.primitives import serialization

# Load current whitelist
with open("whitelist.pkl", "rb") as f:
    whitelist = pickle.load(f)

# Load fob's public key
with open("fob_public.pem", "rb") as f:
    fob_pub_pem = f.read()

# Add if not already present
if fob_pub_pem not in whitelist:
    whitelist.append(fob_pub_pem)
    with open("whitelist.pkl", "wb") as f:
        pickle.dump(whitelist, f)
    print("✅ Fob public key added to whitelist.")
else:
    print("ℹ️  Fob already in whitelist.")
