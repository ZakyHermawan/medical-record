# mbc_node.py

import mbc_crypto as crypto
import hashlib
import json
import time
from pathlib import Path
from pprint import pprint
from flask import Flask, request, jsonify
import requests
import argparse
from threading import Thread, Lock

# --- Consensus Timeout (in seconds) ---
CONSENSUS_TIMEOUT = 30 # 30 seconds

# --- Simulated DNS for Bootstrap Domains ---
SIMULATED_DNS = {
    "bootstrap1.hospital.net": "http://127.0.0.1:5001",
    "bootstrap2.hospital.net": "http://127.0.0.1:5002"
}

# --- Blockchain Logic ---

class Blockchain:
    def __init__(self, node):
        self.node = node 
        self.chain = []
        self.pending_transactions = []
        self.difficulty = 5
    
        self.consensus_signatures = {} 
        
        # store the block being proposed
        self.current_proposal = {}
        
        # Create Genesis Block (as per Slide 11)
        self.create_genesis_block()

    def create_genesis_block(self):
        """Creates the hardcoded Genesis Block (Slide 11)."""
        block = {
            'index': 0,
            'timestamp': 0,
            'transactions': [],
            'patient': 'Claude Shannon', 
            'data': 'Genesis Block',     
            'previous_hash': '0' * 64,
            'proposer': 'CA',
            'nonce': 0,
            'signatures': {} 
        }
        block['hash'] = self.hash_block(block)
        print("Genesis Block created.")
        self.chain.append(block)

    def hash_block(self, block):
        """Hashes a block."""
        # Copy block, remove fields that aren't part of the PoW hash
        block_copy = block.copy()
        block_copy.pop('hash', None)
        block_copy.pop('signatures', None) 
        block_string = json.dumps(block_copy, sort_keys=True).encode('utf-8')
        return hashlib.sha256(block_string).hexdigest()

    # --- Check for failed/timed-out proposals ---
    def check_for_failed_proposal(self):
        """
        Checks if a block has been in consensus for too long.
        If so, it cancels the proposal and returns the transactions
        to the pending pool.
        """
        if not self.current_proposal:
            return 

        start_time = self.current_proposal.get('start_time', 0)
        elapsed = time.time() - start_time

        if elapsed > CONSENSUS_TIMEOUT:
            # --- get block from the proposal structure ---
            block_hash = self.current_proposal.get('block', {}).get('hash', 'unknown')
            print(f"[Proposer] !! Consensus for block {block_hash[:10]}... has TIMED OUT after {elapsed:.0f}s.")
            
            # Get transactions from the failed block
            failed_txs = self.current_proposal.get('block', {}).get('transactions', [])
            
            # Re-add them to the main pending pool
            with self.node.lock:
                print(f"[Proposer] !! Re-adding {len(failed_txs)} transactions to pending pool.")
                self.pending_transactions.extend(failed_txs)
                
            # Clear the failed proposal
            self.current_proposal = {}
            if block_hash in self.consensus_signatures:
                del self.consensus_signatures[block_hash]

    def propose_new_block(self, transactions):
        """
        Combines PoW (main.py) and PoA (PDF).
        Step 1: Find a nonce (PoW).
        Step 2: Propose the block (PoA).
        """
        # Prevent proposing a new block if one is already in consensus
        if self.current_proposal:
             print("[Proposer] !! Cannot propose new block, consensus already in progress.")
             # Re-add the transactions that were meant for this block
             with self.node.lock:
                print("[Proposer] !! Re-adding transactions to pending pool.")
                self.pending_transactions.extend(transactions)
             return

        if not transactions:
            print("[Proposer] !! No transactions to mine.")
            return

        print(f"\n[Proposer] Starting Proof-of-Work for new block with {len(transactions)} txs...")
        
        last_block = self.chain[-1]
        
        # Get patient name from first transaction for the 'patient' field
        patient_name = transactions[0]['transaction']['patient'] if transactions else "N/A"
        
        proposed_block = {
            'index': len(self.chain),
            'timestamp': int(time.time()), 
            'transactions': transactions,
            'patient': patient_name, 
            'data': f"Medical Record for {patient_name} and others.",
            'previous_hash': last_block['hash'],
            'proposer': self.node.node_id
        }
        
        # --- PoW Logic ---
        i = 0
        while True:
            proposed_block['nonce'] = i
            _hash = self.hash_block(proposed_block)
            
            if _hash[:self.difficulty] == '0' * self.difficulty:
                proposed_block['hash'] = _hash
                print(f"[Proposer] PoW Found! Nonce: {i}, Hash: {_hash}")
                break
            i += 1
            if i % 100000 == 0:
                print(f"[Proposer] PoW... (trying nonce {i})")
        # --- End of PoW Logic ---
        
        # --- Store proposal start time *outside* the block ---
        self.current_proposal = {
            'block': proposed_block,
            'start_time': time.time()
        }
        # --- END FIX ---

        # Sign the proposed block
        signature = crypto.sign_data(self.node.private_key, proposed_block['hash'])
        
        # Prepare for PoA consensus
        self.consensus_signatures[proposed_block['hash']] = {
            self.node.node_id: signature.hex()
        }
        
        # Broadcast the proposed block to all peers
        print(f"[Proposer] Broadcasting block {proposed_block['index']} for validation (PoA)...")
        payload = {
            "block": proposed_block,
            "proposer_signature": signature.hex()
        }
        self.node.broadcast_to_peers("/validate_block", payload)

    def validate_and_sign_block(self, block, proposer_signature):
        """
        (Peer) Validates a block proposed by another node (Slide 13).
        """
        print(f"[Peer] Received block {block['index']} from {block['proposer']} for validation.")
        
        # 1. Validate PoW
        _hash = self.hash_block(block)
        if _hash != block['hash'] or _hash[:self.difficulty] != '0' * self.difficulty:
            print(f"[Peer] !! VALIDATION FAILED: Invalid PoW or hash mismatch.")
            return

        # 2. Validate Proposer Signature
        proposer_pub_key = self.node.peer_public_keys.get(block['proposer'])
        if not proposer_pub_key:
            print(f"[Peer] !! VALIDATION FAILED: Don't know public key of {block['proposer']}.")
            return
            
        if not crypto.verify_signature(proposer_pub_key, _hash, bytes.fromhex(proposer_signature)):
            print(f"[Peer] !! VALIDATION FAILED: Proposer signature not valid.")
            return
            
        # 3. Validate Chain (Previous Hash)
        if block['previous_hash'] != self.chain[-1]['hash']:
            # Implement fork resolution
            print(f"[Peer] !! VALIDATION FAILED: Previous hash mismatch. (Fork?)")
            if block['index'] > len(self.chain):
                print(f"[Peer] Fork detected: Their chain (idx {block['index']}) is longer than ours (idx {len(self.chain)-1}).")
                print("[Peer] Requesting full chain from proposer for conflict resolution...")
                # Run in a thread to avoid blocking the validator
                Thread(target=self.node.resolve_conflicts, args=(block['proposer'],)).start()
            else:
                print(f"[Peer] Their chain is shorter or equal (idx {block['index']}). Ignoring fork.")
            return
            
        # 4. Validate all transactions inside the block
        for full_tx in block.get('transactions', []):
            tx = full_tx.get('transaction')
            signature = bytes.fromhex(full_tx.get('signature'))
            node_id = tx.get('node_id')
            
            pub_key = self.node.peer_public_keys.get(node_id)
            if not pub_key and node_id == self.node.node_id: 
                 pub_key = self.node.private_key.public_key()
            
            if not pub_key:
                print(f"[Peer] !! VALIDATION FAILED: Unknown node_id {node_id} for tx.")
                return
            
            if not crypto.verify_json_signature(pub_key, tx, signature):
                print(f"[Peer] !! VALIDATION FAILED: Invalid tx signature from {node_id}.")
                return
        print(f"[Peer] All {len(block.get('transactions', []))} transactions in block are valid.")

        print(f"[Peer] PoW and Proposer Signature Validation SUCCESSFUL.")
        
        # 5. Sign and Send Back (PoA)
        my_signature = crypto.sign_data(self.node.private_key, _hash)
        
        payload = {
            "block_hash": _hash,
            "node_id": self.node.node_id,
            "signature": my_signature.hex()
        }
        
        # Send signature to proposer
        proposer_address = self.node.peer_registry.get(block['proposer'])
        if proposer_address:
            print(f"[Peer] Sending PoA signature to {block['proposer']}.")
            try:
                # --- Increased timeout ---
                requests.post(f"{proposer_address}/submit_signature", json=payload, timeout=5)
            except requests.exceptions.RequestException as e:
                print(f"[Peer] Failed to send signature to proposer: {e}")
        else:
            print(f"[Peer] Cannot find proposer address {block['proposer']} to send signature.")

    def receive_consensus_signature(self, block_hash, node_id, signature):
        """
        (Proposer) Receives consensus signatures from peers (Slide 13).
        """
        if block_hash not in self.consensus_signatures:
            print(f"[Proposer] Received signature for unknown/old block: {block_hash[:10]}...")
            return

        print(f"[Proposer] Received PoA signature from {node_id} for block {block_hash[:10]}...")
        
        # Verify peer signature
        peer_pub_key = self.node.peer_public_keys.get(node_id)
        if not peer_pub_key:
            print(f"[Proposer] !! Failed to verify signature: Don't know public key {node_id}.")
            return
            
        if not crypto.verify_signature(peer_pub_key, block_hash, bytes.fromhex(signature)):
            print(f"[Proposer] !! Failed to verify signature: Signature from {node_id} is NOT VALID.")
            return
            
        # Add signature
        self.consensus_signatures[block_hash][node_id] = signature
        
        # Check if consensus is reached
        total_nodes = len(self.node.peer_public_keys) + 1 # 4 peers + 1 self = 5
        required_signatures = total_nodes # 5 out of 5
        
        current_sig_count = len(self.consensus_signatures[block_hash])
        
        # Add a more verbose log
        print(f"[Proposer] Signature count: {current_sig_count}/{required_signatures}")
        
        if current_sig_count >= required_signatures:
            print(f"[Proposer] *** CONSENSUS REACHED ({current_sig_count}/{required_signatures}) ***")
            Thread(target=self.finalize_and_commit_block, args=(block_hash,)).start()

    def finalize_and_commit_block(self, block_hash):
        """
        (Proposer) Combines all signatures and broadcasts the final block.
        """
        
        # --- Get block from proposal structure ---
        if not self.current_proposal or self.current_proposal.get('block', {}).get('hash') != block_hash:
             print(f"[Proposer] !! Finalization Failed: Block {block_hash[:10]}... is no longer the current proposal.")
             return
             
        final_block = self.current_proposal['block']
        
        final_block['signatures'] = self.consensus_signatures[block_hash]
        
        print(f"[Proposer] Broadcasting FINAL BLOCK {final_block['index']} to all peers.")
        
        # Clear from memory
        del self.consensus_signatures[block_hash]
        self.current_proposal = {}
        
        # Add to local chain
        self.chain.append(final_block)
        print("[Proposer] Final block added to local chain.")
        pprint(final_block)
        
        # Broadcast to all peers
        self.node.broadcast_to_peers("/commit_block", {"block": final_block})

    def commit_block(self, block):
        """(Peer) Receives the final, consensus-approved block."""
        
        print(f"[Peer] Received FINAL BLOCK {block['index']} from {block['proposer']}.")
        
        # Check if already in chain
        if block['hash'] in [b['hash'] for b in self.chain]:
            print(f"[Peer] Block {block['index']} is already in the chain.")
            return

        # Quick validation 
        if block['previous_hash'] != self.chain[-1]['hash']:
            print(f"[Peer] !! Commit failed: Previous hash mismatch.")
            # Handle the case where we missed the proposal but got the commit
            if block['index'] > len(self.chain):
                print(f"[Peer] Fork detected: Commit is for a future block.")
                print("[Peer] Requesting full chain from proposer for conflict resolution...")
                Thread(target=self.node.resolve_conflicts, args=(block['proposer'],)).start()
            return
            
        # Validate all PoA signatures in block['signatures']
        signatures = block.get('signatures', {})
        total_nodes = len(self.node.peer_public_keys) + 1 # +1 for self
        required_signatures = (total_nodes // 2) + 1 # 3 of 5
        
        if len(signatures) < required_signatures:
            print(f"[Peer] !! Commit failed: Not enough signatures. Got {len(signatures)}, required {required_signatures}.")
            return

        verified_sigs = 0
        for node_id, signature_hex in signatures.items():
            pub_key = None
            if node_id == self.node.node_id:
                # It's our own signature
                pub_key = self.node.private_key.public_key()
            else:
                # It's a peer's signature
                pub_key = self.node.peer_public_keys.get(node_id)

            if not pub_key:
                print(f"[Peer] !! Commit failed: Unknown node {node_id} in signature list.")
                continue # Don't fail, just skip
            
            if crypto.verify_signature(pub_key, block['hash'], bytes.fromhex(signature_hex)):
                verified_sigs += 1
            else:
                print(f"[Peer] !! Commit failed: Invalid signature from {node_id}.")
                return # A single invalid signature fails the block
        
        if verified_sigs < required_signatures:
            print(f"[Peer] !! Commit failed: Not enough *valid* signatures. Got {verified_sigs}, required {required_signatures}.")
            return
        
        print(f"[Peer] All {verified_sigs} PoA signatures verified.")
        
        self.chain.append(block)
        print(f"[Peer] Final block {block['index']} added to local chain.")
        pprint(block)

# --- Network Node Class ---

class HospitalNode:
    def __init__(self, node_id, port, bootstrap_domains=None):
        self.node_id = node_id
        self.port = port
        self.address = f"http://127.0.0.1:{port}"
        self.bootstrap_domains = bootstrap_domains or []
        self.certs_dir = Path("certs")
        
        self.app = Flask(__name__)
        self.blockchain = Blockchain(self)
        self.lock = Lock()
        
        # Network Data
        self.peer_registry = {} # On-Chain Registry 
        self.peer_public_keys = {} # Public key cache
        
        # Load identity
        print(f"Loading identity for {node_id}...")
        self.ca_public_key = self.load_ca_public_key()
        self.private_key = self.load_private_key()
        self.certificate = self.load_certificate()
        
        self.register_routes()
        print(f"Node {node_id} starting on port {port}.")

    # --- Load Identity (OOB) ---
    def load_ca_public_key(self):
        with open(self.certs_dir / "ca_public_key.pub", "rb") as f:
            return crypto.load_public_key(f.read())
            
    def load_private_key(self):
        with open(self.certs_dir / self.node_id / "private_key.pem", "rb") as f:
            return crypto.load_private_key(f.read())
            
    def load_certificate(self):
        with open(self.certs_dir / f"{self.node_id}.cert", "r") as f:
            return json.load(f)

    # --- Protocol 1: OOB Handshake ---
    def register_routes(self):
        self.app.add_url_rule("/handshake", "handshake", self.handle_handshake, methods=["POST"])
        self.app.add_url_rule("/add_registry", "add_registry", self.handle_add_registry, methods=["POST"])
        
        # Consensus Endpoints (PoW + PoA)
        self.app.add_url_rule("/validate_block", "validate_block", self.handle_validate_block, methods=["POST"])
        self.app.add_url_rule("/submit_signature", "submit_signature", self.handle_submit_signature, methods=["POST"])
        self.app.add_url_rule("/commit_block", "commit_block", self.handle_commit_block, methods=["POST"])
        
        # External API
        self.app.add_url_rule("/chain", "get_chain", self.get_chain, methods=["GET"])
        self.app.add_url_rule("/peers", "get_peers", self.get_peers, methods=["GET"])
        self.app.add_url_rule("/add_record", "add_record", self.handle_add_record, methods=["POST"])

    def handle_handshake(self):
        """Receives a handshake from a new node."""
        data = request.get_json()
        peer_cert = data.get('certificate')
        
        if not peer_cert:
            return jsonify({"error": "Certificate missing"}), 400
            
        # 1. Verify peer's certificate using CA Pubkey
        if not crypto.verify_json_signature(
            self.ca_public_key,
            peer_cert['cert_data'],
            bytes.fromhex(peer_cert['ca_signature'])
        ):
            print(f"!! HANDSHAKE FAILED: Invalid CA signature from {data.get('address')}")
            return jsonify({"error": "Invalid certificate"}), 401
            
        # 2. Certificate valid, store peer info
        node_id = peer_cert['cert_data']['node_id']
        address = data.get('address')
        pub_key_ssh = peer_cert['cert_data']['public_key']
        
        with self.lock:
            # Only add if not self
            if node_id != self.node_id:
                self.peer_registry[node_id] = address
                self.peer_public_keys[node_id] = crypto.load_public_key(pub_key_ssh.encode('utf-8'))
            
        print(f"++ HANDSHAKE SUCCESSFUL: {node_id} verified at {address}")
        
        # 3. Reply with OWN certificate
        
        with self.lock:
            public_keys_to_send = {
                nid: crypto.serialize_public_key(key).decode('utf-8') 
                for nid, key in self.peer_public_keys.items()
            }

        return jsonify({
            "message": f"Handshake accepted by {self.node_id}",
            "certificate": self.certificate,
            "registry": self.peer_registry, # Send current registry
            "public_keys": public_keys_to_send
        }), 200

    # --- Protocol 2: Peer Discovery ---
    
    def connect_to_bootstrap(self):
        """Contacts the bootstrap node(s) for OOB Handshake."""
        
        # --- Iterate through bootstrap domains for HA ---
        handshake_success = False
        bs_node_id = None # Store the ID of the node we sync with
        
        for domain in self.bootstrap_domains:
            print(f"Contacting Bootstrap at {domain}...")
            
            # Resolve domain using simulated DNS
            bootstrap_address = SIMULATED_DNS.get(domain)
            if not bootstrap_address:
                print(f"!! Could not resolve domain: {domain}")
                continue
                
            payload = {
                "address": self.address,
                "certificate": self.certificate
            }
            try:
                response = requests.post(
                    f"{bootstrap_address}/handshake",
                    json=payload,
                    timeout=5 # Increased timeout
                )
                
                if response.status_code == 200:
                    data = response.json()
                    # Verify bootstrap's certificate
                    if not crypto.verify_json_signature(
                        self.ca_public_key,
                        data['certificate']['cert_data'],
                        bytes.fromhex(data['certificate']['ca_signature'])
                    ):
                        print(f"!! CONNECTION FAILED: Bootstrap {domain} certificate is invalid!")
                        continue # Try next bootstrap
                    
                    print(f"++ Bootstrap Connection SUCCESSFUL with {domain}. Verified.")
                    
                    # Store the bootstrap node's ID for chain syncing
                    bs_node_id = data['certificate']['cert_data']['node_id']
                    
                    # Load registry from bootstrap
                    with self.lock:
                        self.peer_registry.update(data.get('registry', {}))

                        # Load all public keys received from the bootstrap
                        received_keys = data.get('public_keys', {})
                        for node_id, pub_key_ssh in received_keys.items():
                            if node_id != self.node_id: # Don't add self
                                # Only add if we don't already know this key
                                if node_id not in self.peer_public_keys:
                                    print(f"[Bootstrap] Learning key for {node_id} from bootstrap.")
                                    self.peer_public_keys[node_id] = crypto.load_public_key(pub_key_ssh.encode('utf-8'))

                        # Add bootstrap to registry
                        if bs_node_id != self.node_id:
                            self.peer_registry[bs_node_id] = bootstrap_address
                            self.peer_public_keys[bs_node_id] = crypto.load_public_key(
                                data['certificate']['cert_data']['public_key'].encode('utf-8')
                            )
                    
                    handshake_success = True
                    # We successfully connected to one, so we can stop
                    break 
                else:
                    print(f"!! Handshake FAILED with {domain}: {response.text}")
                    
            except requests.exceptions.RequestException as e:
                print(f"!! Failed to connect to Bootstrap {domain}: {e}")
        
        # After loop, check if we ever succeeded
        if handshake_success:
            # --- PROACTIVE SYNC ---
            # Now that we've connected, immediately sync our chain
            print(f"--- Proactively syncing chain with {bs_node_id} ---")
            self.resolve_conflicts(bs_node_id) 
            
            # Now we can broadcast our registry entry
            self.broadcast_registry_entry()
        else:
            print("!! FATAL: Could not connect to any bootstrap nodes. Shutting down.")
            return

    def broadcast_registry_entry(self):
        """Broadcasts this node's info to all known peers."""
        print("Broadcasting self registry entry to all peers...")
        payload = {
            "node_id": self.node_id,
            "address": self.address,
            "public_key_ssh": crypto.serialize_public_key(self.private_key.public_key()).decode('utf-8')
        }
        # Sign the data
        signature = crypto.sign_json(self.private_key, payload)
        
        self.broadcast_to_peers("/add_registry", {
            "data": payload,
            "signature": signature.hex()
        })
        
    def handle_add_registry(self):
        """Receives a registry entry from another peer."""
        data = request.get_json()
        payload = data.get('data')
        signature = bytes.fromhex(data.get('signature'))
        
        node_id = payload.get('node_id')
        address = payload.get('address')
        public_key_ssh = payload.get('public_key_ssh')
        
        # Verify signature
        pub_key = crypto.load_public_key(public_key_ssh.encode('utf-8'))
        
        if not crypto.verify_json_signature(pub_key, payload, signature):
            print(f"!! Failed to add registry: Invalid signature from {node_id}")
            return jsonify({"error": "Invalid signature"}), 401
            
        is_new_peer = False # Flag to check if we need to gossip
        with self.lock:
            if node_id != self.node_id:
                current_address = self.peer_registry.get(node_id)
                if current_address != address:
                    print(f"++ REGISTRY UPDATED: Node {node_id} is now at {address}")
                    self.peer_registry[node_id] = address
                    self.peer_public_keys[node_id] = pub_key
                    is_new_peer = True # This is a new/updated peer
                else:
                    pass 
        
        # --- NEW GOSSIP PROTOCOL ---
        # If this was a new peer, tell everyone else about them.
        if is_new_peer:
            print(f"[Gossip] Broadcasting new peer info for {node_id} to all other peers...")
            # We re-broadcast the *original message* (data, not payload)
            self.broadcast_to_peers("/add_registry", data, exclude_node_id=node_id)
                
        return jsonify({"message": "Registry accepted"}), 200

    def broadcast_to_peers(self, endpoint, payload, exclude_node_id=None):
        """Sends a message to all peers in the registry."""
        with self.lock:
            peers_to_broadcast = self.peer_registry.copy()
            
        for node_id, address in peers_to_broadcast.items():
            if address == self.address: # Don't send to self
                continue
            if node_id == exclude_node_id: # Don't send back to originator
                continue
                
            try:
                url = f"{address}{endpoint}"
                requests.post(url, json=payload, timeout=5) # Increased timeout
            except requests.exceptions.RequestException:
                print(f"!! Failed to send to peer {node_id} at {address}")
                
    # --- Function for Fork Resolution ---
    def validate_full_chain(self, chain):
        """Validates an entire blockchain received from a peer."""
        print("[Fork] Validating incoming chain...")
        # Check genesis block
        if json.dumps(chain[0], sort_keys=True) != json.dumps(self.blockchain.chain[0], sort_keys=True):
            print("[Fork] !! Validation Failed: Genesis blocks do not match.")
            return False
            
        # Validate all other blocks
        for i in range(1, len(chain)):
            block = chain[i]
            last_block = chain[i-1]
            
            # Check hash link
            if block['previous_hash'] != last_block['hash']:
                print(f"[Fork] !! Validation Failed: Chain link broken at index {i}.")
                return False
                
            # Check PoW
            _hash = self.blockchain.hash_block(block)
            if _hash != block['hash'] or _hash[:self.blockchain.difficulty] != '0' * self.blockchain.difficulty:
                print(f"[Fork] !! Validation Failed: Invalid PoW at index {i}.")
                return False
            
        print("[Fork] Incoming chain is valid.")
        return True

    def resolve_conflicts(self, proposer_node_id):
        """Handles fork resolution by finding the longest valid chain."""
        print("[Fork] Resolving conflicts...")
        
        proposer_address = self.peer_registry.get(proposer_node_id)
        if not proposer_address:
            # Check if proposer is self (edge case)
            if proposer_node_id == self.node_id:
                proposer_address = self.address
            else:
                print(f"[Fork] Cannot resolve, unknown proposer {proposer_node_id}.")
                return
            
        try:
            response = requests.get(f"{proposer_address}/chain", timeout=5)
            if response.status_code != 200:
                print(f"[Fork] Failed to get chain from {proposer_node_id}.")
                return
                
            new_chain = response.json()
            
            with self.lock:
                if len(new_chain) > len(self.blockchain.chain) and self.validate_full_chain(new_chain):
                    print(f"[Fork] Replacing local chain (length {len(self.blockchain.chain)}) with new chain (length {len(new_chain)}).")
                    self.blockchain.chain = new_chain
                else:
                    print("[Fork] Local chain is authoritative. Ignoring incoming chain.")

        except requests.exceptions.RequestException as e:
            print(f"[Fork] Error during conflict resolution: {e}")

    # --- Consensus Endpoints (PoW + PoA) ---
    
    def handle_validate_block(self):
        """Receives a proposed block for validation."""
        data = request.get_json()
        block = data.get('block')
        signature = data.get('proposer_signature')
        
        # Run validation in a separate thread to avoid blocking
        Thread(target=self.blockchain.validate_and_sign_block, args=(block, signature)).start()
        
        return jsonify({"message": "Validation accepted"}), 202

    def handle_submit_signature(self):
        """Receives a PoA signature from a peer."""
        data = request.get_json()
        block_hash = data.get('block_hash')
        node_id = data.get('node_id')
        signature = data.get('signature')
        
        with self.lock:
            self.blockchain.receive_consensus_signature(block_hash, node_id, signature)
            
        return jsonify({"message": "Signature received"}), 200

    def handle_commit_block(self):
        """Receives the final, consensus-approved block."""
        data = request.get_json()
        block = data.get('block')
        
        with self.lock:
            self.blockchain.commit_block(block)
            
        return jsonify({"message": "Block committed"}), 200

    # --- External API ---
    
    def get_chain(self):
        return jsonify(self.blockchain.chain), 200
        
    def get_peers(self):
        return jsonify(self.peer_registry), 200
        
    def handle_add_record(self):
        """
        API for a user to add a new medical record.
        This node will automatically become the proposer and start mining.
        """
        data = request.get_json()
        patient = data.get('patient')
        record_data = data.get('data')
        
        if not patient or not record_data:
            return jsonify({"error": "'patient' and 'data' fields are required"}), 400
        
        # --- Check for timed-out proposals first ---
        with self.lock:
            self.blockchain.check_for_failed_proposal()
            
        # Create transaction
        tx = {
            "timestamp": int(time.time()), 
            "patient": patient,
            "data": record_data,
            "node_id": self.node_id
        }
        
        # Sign transaction
        signature = crypto.sign_json(self.private_key, tx)
        
        full_tx = {"transaction": tx, "signature": signature.hex()}
        
        # Add to own pending pool
        with self.lock:
            self.blockchain.pending_transactions.append(full_tx)
        
        # --- Automatically start mining ---
        with self.lock:
            if not self.blockchain.pending_transactions:
                return jsonify({"message": "No transactions to mine"}), 400 # Should not happen
            if self.blockchain.current_proposal:
                print("[API] Consensus already in progress, tx added to pool.")
                return jsonify({"message": "Consensus already in progress, tx added to pool"}), 409 # 409 Conflict
                
            tx_to_mine = self.blockchain.pending_transactions[:] # Get a copy
            self.blockchain.pending_transactions.clear() # Clear the pool
        
        print(f"\nAPI: /add_record triggered. Proposing block with {len(tx_to_mine)} transactions...")
        # Run PoW/PoA in a thread
        Thread(target=self.blockchain.propose_new_block, args=(tx_to_mine,)).start()
        
        return jsonify({"message": "Block proposal started"}), 202
        
    def run(self):
        # --- Run connect_to_bootstrap *before* starting the server ---
        if self.bootstrap_domains:
            # This is NOT a primary bootstrap node.
            # We must connect and sync *before* starting the server.
            # This is a synchronous, blocking call.
            self.connect_to_bootstrap()
        
        print("\n--- Node is online and ready. ---")
            
        # Add threaded=True to prevent deadlocks
        self.app.run(port=self.port, host="0.0.0.0", threaded=True)

# --- Main execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Medical Blockchain Node")
    parser.add_argument('-i', '--id', required=True, type=str, help='Node ID (e.g., RS-1)')
    parser.add_argument('-p', '--port', required=True, type=int, help='Port for the node')
    # --- MODIFIED: Accept multiple bootstrap domains ---
    parser.add_argument('-b', '--bootstrap', action='append', help='Bootstrap domain (e.g., bootstrap1.hospital.net)')
    args = parser.parse_args()

    node = HospitalNode(node_id=args.id, port=args.port, bootstrap_domains=args.bootstrap)
    node.run()

