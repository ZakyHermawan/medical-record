# mbc_crypto.py

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
import json

# --- Function from keygen.py ---

def generate_keys():
    """Creating new pair Ed25519 key."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_private_key(private_key):
    """Changing private key to PEM."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def serialize_public_key(public_key):
    """Changing public key menjadi OpenSSH."""
    # Format ini sesuai dengan output di keygen.py
    return public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )

def load_private_key(pem_bytes):
    """Load private key from PEM."""
    return serialization.load_pem_private_key(pem_bytes, password=None)

def load_public_key(ssh_bytes):
    """Load public key from format OpenSSH."""
    # Menggunakan load_ssh_public_key yang sesuai
    return serialization.load_ssh_public_key(ssh_bytes)

# --- Fungsi dari main.py ---

def sign_data(private_key, data):
    """Sign data (string) using private key."""
    if not isinstance(data, bytes):
        data_bytes = data.encode('utf-8')
    else:
        data_bytes = data
        
    return private_key.sign(data_bytes)

def verify_signature(public_key, data, signature):
    """Verified tsignature to real data using public key."""
    if not isinstance(data, bytes):
        data_bytes = data.encode('utf-8')
    else:
        data_bytes = data
        
    try:
        public_key.verify(signature, data_bytes)
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"Error when verification: {e}")
        return False

def sign_json(private_key, data_dict):
    """
    Sign JSON data consistent.
    chang dict -> string JSON sorted -> bytes -> signature.
    """
    canonical_string = json.dumps(data_dict, sort_keys=True)
    return sign_data(private_key, canonical_string)

def verify_json_signature(public_key, data_dict, signature):
    """Verify signed JSON data."""
    canonical_string = json.dumps(data_dict, sort_keys=True)
    return verify_signature(public_key, canonical_string, signature)