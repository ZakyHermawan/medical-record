# mbc_ca.py

import mbc_crypto as crypto
from pathlib import Path
import json

# --- Configuration ---
NODE_IDS = ["RS-1", "RS-2", "RS-3", "RS-4", "RS-5"]
CERTS_DIR = Path("certs")

def main():
    print("--- Start Out-of-Band (OOB) Secure Initial Setup ---")
    
    # 1. Create certs director
    CERTS_DIR.mkdir(exist_ok=True)
    
    # Create Master CA Key(Registrar)
    print("Creating master CA key (Registrar)...")
    ca_priv_key, ca_pub_key = crypto.generate_keys()
    
    ca_priv_path = CERTS_DIR / "ca_private_key.pem"
    ca_pub_path = CERTS_DIR / "ca_public_key.pub" 
    
    with open(ca_priv_path, "wb") as f:
        f.write(crypto.serialize_private_key(ca_priv_key))
    with open(ca_pub_path, "wb") as f:
        f.write(crypto.serialize_public_key(ca_pub_key))
        
    print(f"Kunci CA disimpan di {CERTS_DIR}/")

    # 3. Create Key and Certificate for every Node
    print("\nCreate Key and Certificate for every Hospital Node...")
    for node_id in NODE_IDS:
        node_dir = CERTS_DIR / node_id
        node_dir.mkdir(exist_ok=True)
        
        node_priv_key, node_pub_key = crypto.generate_keys()
        
        priv_path = node_dir / "private_key.pem"
        pub_path = node_dir / "public_key.pub"
        with open(priv_path, "wb") as f:
            f.write(crypto.serialize_private_key(node_priv_key))
        with open(pub_path, "wb") as f:
            f.write(crypto.serialize_public_key(node_pub_key))
            
        # 4. Create Certificate
        print(f"Launch certificate for {node_id}...")
        
        cert_data = {
            "node_id": node_id,
            "public_key": crypto.serialize_public_key(node_pub_key).decode('utf-8')
        }
        
        signature = crypto.sign_json(ca_priv_key, cert_data)
        
        certificate = {
            "cert_data": cert_data,
            "ca_signature": signature.hex()
        }
        
        # Save Certificate
        cert_path = CERTS_DIR / f"{node_id}.cert"
        with open(cert_path, "w") as f:
            json.dump(certificate, f, indent=2)
            
    print("\n--- OOB Setup End ---")
    print(f"Every key and certificati is in directory '{CERTS_DIR}'.")

if __name__ == "__main__":
    main()
