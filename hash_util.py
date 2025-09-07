import hashlib

def sha256_hash(data: bytes):
    hash_obj = hashlib.sha256()
    hash_obj.update(data)
    return hash_obj.hexdigest(), hash_obj.digest()

