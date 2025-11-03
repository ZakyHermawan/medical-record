import mbc_crypto as crypto
import json
import time
from pathlib import Path
from flask import Flask, request, jsonify, render_template, redirect, url_for
import requests
from threading import Thread, Lock

from mbc_blockchain import Blockchain
from datetime import datetime

# --- Simulated DNS for Bootstrap Domains ---
SIMULATED_DNS = {
    "bootstrap1.hospital.net": "http://127.0.0.1:5001",
    "bootstrap2.hospital.net": "http://127.0.0.1:5002"
}

# --- Network Node Class (Combines Everything) ---

class HospitalNode:
    def __init__(self, node_id, port, bootstrap_domains=None):
        self.node_id = node_id
        self.port = port
        self.address = f"http://127.0.0.1:{port}"
        self.bootstrap_domains = bootstrap_domains or []
        self.certs_dir = Path("certs")
        
        self.app = Flask(__name__)

        @self.app.template_filter('to_datetime')
        def format_timestamp(timestamp):
            """Converts a UNIX timestamp to a readable string."""
            if timestamp == 0:
                # Special case for the Genesis Block
                return "1970-01-01 00:00:00 (Genesis)"
            try:
                dt = datetime.fromtimestamp(timestamp)
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            except (ValueError, TypeError):
                return "Invalid Timestamp"

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
        self.app.add_url_rule("/", "show_home_page", self.show_home_page, methods=["GET"])

        self.app.add_url_rule("/handshake", "handshake", self.handle_handshake, methods=["POST"])
        self.app.add_url_rule("/add_registry", "add_registry", self.handle_add_registry, methods=["POST"])

        # Consensus Endpoints (PoW + PoA)
        self.app.add_url_rule("/validate_block", "validate_block", self.handle_validate_block, methods=["POST"])
        self.app.add_url_rule("/submit_signature", "submit_signature", self.handle_submit_signature, methods=["POST"])
        self.app.add_url_rule("/commit_block", "commit_block", self.handle_commit_block, methods=["POST"])

        # External API
        self.app.add_url_rule("/chain", "get_chain", self.get_chain, methods=["GET"])
        self.app.add_url_rule("/peers", "get_peers", self.get_peers, methods=["GET"])

        # add_record to handle both POST (from form) and JSON
        self.app.add_url_rule("/add_record", "add_record", self.handle_add_record, methods=["POST"])

    def show_home_page(self):
        """Renders the HTML form to add a new record."""
        return render_template('index.html', node_id=self.node_id)

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
        
        # --- GOSSIP PROTOCOL ---
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
        """Renders the blockchain as an HTML page (for humans)."""
        with self.lock:
            # Get a copy of the chain to avoid issues during iteration
            chain_data = list(self.blockchain.chain)

        return render_template('blocks.html',
                               blocks=chain_data,
                               title=f"Blockchain for {self.node_id}",
                               node_id=self.node_id,
                               data=self.blockchain.chain)
        
    def get_peers(self):
        return jsonify(self.peer_registry), 200
        
    def handle_add_record(self):
        """
        API for a user to add a new medical record.
        This node will automatically become the proposer and start mining.
        
        This function is multi-purpose:
        - It handles JSON requests (from curl, scripts, or other nodes)
        - It handles Form-Data requests (from the new index.html web form)
        """

        is_form_submission = False

        if request.is_json:
            # Handle API/JSON request
            data = request.get_json()
            patient = data.get('patient')
            record_data = data.get('data')
        else:
            # Handle Web Form request
            data = request.form
            patient = data.get('patient')
            record_data = data.get('data')
            is_form_submission = True

        if not patient or not record_data:
            error_msg = {"error": "'patient' and 'data' fields are required"}
            if is_form_submission:
                # TODO: Could render an error template
                return jsonify(error_msg), 400
            return jsonify(error_msg), 400

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
                # This should not happen, but good to check
                msg = {"message": "No transactions to mine"}
                return jsonify(msg), 400

            if self.blockchain.current_proposal:
                print("[API] Consensus already in progress, tx added to pool.")
                msg = {"message": "Consensus already in progress, tx added to pool"}
                if is_form_submission:
                    # Redirect to chain, the tx will be mined eventually
                    return redirect(url_for('get_chain'))
                return jsonify(msg), 409 # 409 Conflict

            tx_to_mine = self.blockchain.pending_transactions[:] # Get a copy
            self.blockchain.pending_transactions.clear() # Clear the pool

        print(f"\nAPI: /add_record triggered. Proposing block with {len(tx_to_mine)} transactions...")
        # Run PoW/PoA in a thread
        Thread(target=self.blockchain.propose_new_block, args=(tx_to_mine,)).start()

        # --- Respond based on request type ---
        if is_form_submission:
            # Redirect user to the chain visualizer!
            return redirect(url_for('get_chain'))
        else:
            # Return JSON for API calls
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
