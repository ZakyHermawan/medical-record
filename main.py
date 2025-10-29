from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

import hashlib  
from time import time
from pprint import pprint

def sign_data(private_key, data):
    """Signs a piece of data using the private key."""
    # Data must be in bytes before signing
    data_bytes = data.encode('utf-8')
    
    # Use the sign method from the Ed25519PrivateKey object
    signature = private_key.sign(data_bytes)
    print(f"Signature generated (Length: {len(signature)} bytes)")
    return signature

def verify_signature(public_key, data, signature):
    """Verifies a signature against the original data using the public key."""
    data_bytes = data.encode('utf-8')
    
    try:
        # If verification fails, this method raises InvalidSignature
        public_key.verify(signature, data_bytes)
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"An error occurred during verification: {e}")
        return False

# this function can be used to store private key to file (just put the private_pem.decode() content into a .pem file)
def print_private_key(private_key):
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    print("\n[Private Key (PKCS8 PEM format)]")
    print(private_pem.decode())

# this function can be used to store public key to file (just put the public_openssh.decode() content into a .pem file)
def print_public_key(public_key):
    public_openssh = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )
    print("\n[Public Key (OpenSSH format)]")
    print(public_openssh.decode())

class blockchain():
    def __init__(self):
        self.blocks = []
        self.__secret = ''
        self.__difficulty = 5 
        # guessing the nonce
        nonce = 0
        secret_string = '/*SECRET*/'

        # genesis block
        block = {
            'index': 0,
            'patient': 'Claude Shannon',
            'data': 'Genesis Block',
            'previous_hash': '0' * 64
        }
        while True:
            _hash = hashlib.sha256(str(secret_string+str(nonce)).encode('utf-8')).hexdigest()
            if(_hash[:self.__difficulty] == '0'*self.__difficulty):
                self.__secret = _hash
                block['hash'] = _hash
                self.blocks.append(block)
                break
            nonce+=1
    def create_block(self, patient:str, data:str):
        # data
        block = {
            'index': len(self.blocks),
            'patient': patient,
            'info': data
        }
        if(block['index'] == 0): block['previous_hash'] = self.__secret # for genesis block
        else: block['previous_hash'] = self.blocks[-1]['hash']
        # guessing the nonce
        i = 0
        while True:
            block['nonce'] = i
            _hash = hashlib.sha256(str(block).encode('utf-8')).hexdigest()
            if(_hash[:self.__difficulty] == '0'*self.__difficulty):
                block['hash'] = _hash
                break
            i+=1
        self.blocks.append(block)
    def validate_blockchain(self):
        valid = True
        n = len(self.blocks)-1
        i = 0
        while(i<n):
            if(self.blocks[i]['hash'] != self.blocks[i+1]['previous_hash']):
                valid = False
                break
            i+=1
        if valid: print('The blockchain is valid...')
        else: print('The blockchain is not valid...')
    def show_blockchain(self):
        for block in self.blocks: 
            pprint(block)
            print()

b = blockchain()
b.create_block('Alice', 'TBC')
b.create_block('Bob', 'Diabetes')
b.show_blockchain()
b.validate_blockchain()

priv_keys = []
public_keys = []
datas = []
signatures = []

# how to sign data
for i in range(3):
    # Generate key pairs
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    priv_keys.append(private_key)
    public_keys.append(public_key)

    print_private_key(private_key)
    print_public_key(public_key)

    # Sign some data
    data = f"Patient record {i}: Confidential medical data."
    datas.append(data)
    signature = sign_data(private_key, data)
    signatures.append(signature)

print("Validating blocks signatures...")
# how to verify signatures
for i in range(3):
    public_key = public_keys[i]
    data = datas[i]
    signature = signatures[i]

    is_valid = verify_signature(public_key, data, signature)
    print(f"Signature valid: {is_valid}")
    if not is_valid:
        print("Signature verification failed!")
        exit(1)
