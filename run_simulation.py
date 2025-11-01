import os
import time
import sys
from pathlib import Path
from threading import Thread

# --- Configuration ---
# Use 5 nodes as start
HOSPITAL_IDS = ["RS-1", "RS-2", "RS-3", "RS-4", "RS-5"]
BASE_PORT = 5000
NODE_PORTS = {f"RS-{i+1}": BASE_PORT + i + 1 for i in range(len(HOSPITAL_IDS))}

# --- Define bootstrap domains ---
BOOTSTRAP_DOMAINS = ["bootstrap1.hospital.net", "bootstrap2.hospital.net"]
# Map nodes to their "domain"
NODE_TO_DOMAIN_MAP = {
    "RS-1": "bootstrap1.hospital.net",
    "RS-2": "bootstrap2.hospital.net"
}
# ---

# Function to start a single node in a new terminal window
def start_node(node_id, port, bootstrap_domains=None):
    """
    Starts a node in a new terminal.
    Uses 'start' for Windows and 'osascript' for macOS.
    """
    print(f"--- Starting Node {node_id} on port {port} ---")
    
    # Build the bootstrap arguments
    bootstrap_args = ""
    if bootstrap_domains:
        for domain in bootstrap_domains:
            bootstrap_args += f' -b {domain}' # Add -b flag for each bootstrap domain
            
    # Build the full command
    python_executable = sys.executable
    command = f'"{python_executable}" mbc_node.py -i {node_id} -p {port}{bootstrap_args}'
    
    try:
        if sys.platform == "win32":
            # For Windows:
            return_code = os.system(f'start "Hospital Node {node_id}" cmd /k "{command}"')
            if return_code != 0:
                raise Exception(f"Failed to start terminal. Error code: {return_code}")
                
        elif sys.platform == "darwin":
            # For macOS:
            script = f'tell app "Terminal" to do script "{command}"'
            return_code = os.system(f"osascript -e '{script}'")
            if return_code != 0:
                raise Exception(f"Failed to start terminal. Error code: {return_code}")
                
        else:
            # For Linux
            print(f"Linux: Attempting to open in new terminal...")
            
            # Try gnome-terminal
            gnome_command = f'gnome-terminal -- bash -c "{command}; exec bash" &'
            return_code = os.system(gnome_command)
            
            if return_code != 0:
                print(f"gnome-terminal failed (code: {return_code}), trying xterm...")
                # Try xterm as fallback
                xterm_command = f'xterm -e "bash -c \\"{command}; exec bash\\"" &'
                return_code = os.system(xterm_command)
                
                if return_code != 0:
                     print(f"xterm also failed (code: {return_code}).")
                     raise Exception("No compatible terminal emulator (gnome-terminal, xterm) found.")
            
            print(f"Linux: Successfully launched terminal.")

    except Exception as e:
        print(f"!! FAILED to start node {node_id} automatically: {e}")
        print("!! Please run the following command in a new terminal:")
        print(f"   {command}")

# Function to run the simulation
def run_simulation():
    # 1. Check if CA files exist
    if not Path("certs/ca_public_key.pub").exists():
        print("="*60)
        print("!! ERROR: Certificate Authority files not found in 'certs/'.")
        print("!! Please run 'python mbc_ca.py' first to set up the network.")
        print("="*60)
        return

    # 2. Start all nodes
    try:
        processes = []
        
        # ---  STARTUP LOGIC TO PREVENT FRAGMENTED NETWORK ---
        
        # 1. Start RS-1 (Primary Bootstrap)
        print("Starting RS-1 (Primary Bootstrap)...")
        t_rs1 = Thread(target=start_node, args=("RS-1", NODE_PORTS["RS-1"], None))
        t_rs1.start()
        processes.append(t_rs1)
        print("Waiting for RS-1 to be online...")
        time.sleep(4) # Give server time to start

        # 2. Start RS-2 (Secondary Bootstrap)
        # links the two bootstraps.
        print("Starting RS-2 (Secondary Bootstrap), connecting to RS-1...")
        t_rs2 = Thread(target=start_node, args=("RS-2", NODE_PORTS["RS-2"], [BOOTSTRAP_DOMAINS[0]])) # Pass RS-1's domain
        t_rs2.start()
        processes.append(t_rs2)
        print("Waiting for RS-2 to connect and register...")
        time.sleep(3) # Give time for handshake

        # 3. Start all other nodes
        # connect to *both* RS-1 and RS-2 for high availability.
        print("Starting all remaining nodes (RS-3, RS-4, RS-5)...")
        for node_id in HOSPITAL_IDS:
            if node_id in ["RS-1", "RS-2"]:
                continue 
                
            port = NODE_PORTS[node_id]
            # Pass the full list of bootstrap DOMAINS to the other nodes
            t = Thread(target=start_node, args=(node_id, port, BOOTSTRAP_DOMAINS))
            t.start()
            processes.append(t)
            time.sleep(1) # Stagger starts

        # --- END STARTUP LOGIC ---

        print("\n--- All 5 nodes are starting up. ---")
        print("--- RS-3, RS-4, and RS-5 will now connect to RS-1 or RS-2. ---")
        
        # Wait for all threads to start
        for p in processes:
            p.join()

        # 3. Print instructions for testing
        print("\n" + "="*60)
        print("      NETWORK IS RUNNING. 5 TERMINALS SHOULD BE OPEN.")
        print("="*60)
        print("\nTo test the network, open a NEW terminal and send a record:")
        
        test_port = NODE_PORTS["RS-3"] # Send to a non-bootstrap node
        
        print(f"\n--- Windows (Command Prompt) ---")
        json_payload_windows = '"{\\"patient\\": \\"Alice\\", \\"data\\": \\"High Fever\\"}"'
        print(f'curl -X POST http://127.0.0.1:{test_port}/add_record -H "Content-Type: application/json" -d {json_payload_windows}')
        
        print(f"\n--- macOS / Linux (Bash) ---")
        json_payload_unix = '\'{"patient": "Alice", "data": "High Fever"}\''
        print(f"curl -X POST http://127.0.0.1:{test_port}/add_record -H 'Content-Type: application/json' -d {json_payload_unix}")
        
        print("\n" + "="*60)
        print("To test HIGH AVAILABILITY:")
        print("1. Close the terminal for 'RS-1' (Bootstrap 1).")
        print("2. Close the terminal for 'RS-4' (a regular node).")
        print("3. Restart 'RS-4' by running this in a new terminal:")
        print(f"   \"{sys.executable}\" mbc_node.py -i RS-4 -p {NODE_PORTS['RS-4']} -b {BOOTSTRAP_DOMAINS[0]} -b {BOOTSTRAP_DOMAINS[1]}")
        print("\n... 'RS-4' should print 'Failed to connect to bootstrap1...' and then 'Bootstrap Connection SUCCESSFUL with bootstrap2...'")

    except KeyboardInterrupt:
        print("\n--- Simulation launcher stopped. ---")
        print("--- (Note: Node terminals must be closed manually) ---")

if __name__ == "__main__":
    run_simulation()

