import mbc_crypto as crypto
import hashlib
import json
import time
from pprint import pprint
import requests
from threading import Thread
from datetime import datetime

# --- Consensus Timeout (in seconds) ---
CONSENSUS_TIMEOUT = 30 # 30 seconds

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

        block_copy = block.copy()
        block_copy.pop('hash', None)
        block_copy.pop('signatures', None)

        i = 0
        while True:
            block_copy['nonce'] = i
            block_string = json.dumps(block_copy, sort_keys=True).encode('utf-8')
            _hash = hashlib.sha256(block_string).hexdigest()

            if _hash[:self.difficulty] == '0' * self.difficulty:
                block['hash'] = _hash
                break

            i += 1
            if i % 100000 == 0:
                print(f"[Proposer] PoW... (trying nonce {i})")

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
