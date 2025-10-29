from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# 1. Generate the Private Key
private_key = ed25519.Ed25519PrivateKey.generate()

# 2. Derive the Public Key
public_key = private_key.public_key()

# 3. Serialize (Export) the Private Key (e.g., to PEM format)
private_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption() # Use a password for production!
)
print("--- Serialized Private Key (PEM) ---")
print(private_bytes.decode())

# 4. Serialize (Export) the Public Key (e.g., to OpenSSH format)
public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.OpenSSH,
    format=serialization.PublicFormat.OpenSSH
)
print("\n--- Serialized Public Key (OpenSSH) ---")
print(public_bytes.decode())

# Example of saving keys to files (optional)
with open("private_key.pem", "wb") as f:
    f.write(private_bytes)
with open("public_key.pub", "wb") as f:
    f.write(public_bytes)
