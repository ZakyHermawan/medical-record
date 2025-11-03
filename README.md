# Medical Record Blockchain (MBC) Simulation

This document provides step-by-step instructions for setting up, running, and testing the 5-node Medical Record Blockchain (MBC) simulation.

## 1. Project Overview

This project simulates a private, permissioned blockchain network for 5 hospitals (**RS-1** to **RS-5**). It is designed to run on a single machine by launching each node in a separate terminal.

**Key Features:**

* **5-Node Network:** Simulates 5 distinct hospital nodes.
* **Hybrid Consensus (PoW + PoA):** A node must solve a **Proof-of-Work (PoW)** puzzle to propose a block, and **all 5 nodes** must sign it (**Proof-of-Authority/PoA**) for it to be valid.
* **Out-of-Band (OOB) Setup:** Uses a **Certificate Authority** (`mbc_ca.py`) to generate trusted "digital passports" (certificates) for each node.
* **High-Availability (HA) Bootstraps:** Uses two bootstrap nodes (`RS-1`, `RS-2`) with "domain names" (`bootstrap1.hospital.net`, `bootstrap2.hospital.net`) for network failover.
* **Gossip Protocol:** Nodes automatically share peer information to ensure the network registry is fully connected.
* **Fork Resolution:** Re-joining nodes automatically detect they are behind, request the longest valid chain, and sync up before coming online.

## 2. File Structure

Your project folder must contain these four Python files:

1.  `mbc_ca.py`: **(Certificate Authority)** Run *once* to generate all keys and certificates.
2.  `mbc_crypto.py`: **(Crypto Library)** Imported by other scripts. Do not run directly.
3.  `mbc_node.py`: **(Node Program)** The main code for a single hospital node.
4.  `run_simulation.py`: **(Launcher Script)** Starts the 5-node simulation.

## 3. Phase 1: Setup (Run Once)

This phase creates the `certs` directory, which contains all the cryptographic keys and certificates for the 5 hospitals.

### Step 1. Install Dependencies

Open your terminal and install the required Python libraries:

```bash
pip install flask requests cryptography
```

### Step 2. Run the Certificate Authority (CA)
In the same terminal, run the `mbc_ca.py` script:

```bash
python mbc_ca.py
```

Expected Output: You will see logs like `Creating CA master key...`, `Issuing certificate for RS-1...`, etc.

Result: A new folder named `certs` will be created in your project directory. You only need to do this step once.

## 4. Phase 2: Start the 5-Node Network
This will launch 5 separate terminal windows, one for each hospital node.

In your terminal, run the `mbc_launcher.py` script:
```bash
python mbc_launcher.py
```
Expected Output:
1. Your main terminal will print `--- Starting Node RS-1 on port 5001 ---, --- Starting Node RS-2 on port 5002 ---`, etc.

2. 5 new terminal windows will open (one for each node).

3. The terminals for `RS-3`, `RS-4`, and `RS-5` will log `Contacting Bootstrap...`, `Bootstrap Connection SUCCESSFUL...`, and `Broadcasting self registry entry....`

4. You will see all terminals start printing `++ REGISTRY UPDATED...` as the gossip protocol shares peer info.

5. After about 10-15 seconds, all nodes will be silent and stable, and all 5 nodes should know about all 4 of their peers.

6. Your main terminal (where you ran the script) will display instructions for Phase 3.

Your 5-node blockchain is now online and running.

## 5. Phase 3: Test the Network (Add a Block)
Now you will propose a new block. The system is designed so you can send the request to any node, and that node will become the proposer.

1. Open a NEW terminal (do not use any of the 5 running node terminals).
 
2. Run one of the following `curl` commands to send a new record to `RS-3` (port 5003).

If you are on Windows (Command Prompt):
```bash
curl -X POST [http://127.0.0.1:5003/add_record](http://127.0.0.1:5003/add_record) -H "Content-Type: application/json" -d "{\"patient\": \"Alice\", \"data\": \"High Fever\"}"
```

If you are on macOS or Linux (Bash):
```bash
curl -X POST [http://127.0.0.1:5003/add_record](http://127.0.0.1:5003/add_record) -H 'Content-Type: application/json' -d '{"patient": "Alice", "data": "High Fever"}'
```
* Expected Output (Watch all 5 node terminals):

1. RS-3 Terminal: Will log `API: /add_record triggered...`, then `[Proposer] Starting Proof-of-Work....` It will print `PoW...` until it finds a valid hash.

2. All Other Terminals: Will log `[Peer] Received block 1 from RS-3 for validation...`, `PoW and Proposer Signature Validation SUCCESSFUL.`, and `[Peer] Sending PoA signature to RS-3.`.

3. RS-3 Terminal: Will log `[Proposer] Received PoA signature from...` four times, followed by `[Proposer] Signature count: 5/5` and `[Proposer] *** CONSENSUS REACHED (5/5) ***`.

4. All 5 Terminals: Will log `[Peer] Received FINAL BLOCK 1...` and print the full, finalized block.

## 6. Phase 4: View the Blockchain
At any time, you can inspect the full blockchain from any node.

1. Open a NEW terminal.

2. Run the following `curl` command. You can use the port of any running node (e.g., 5001, 5002, 5003, 5004, or 5005).

```bash
curl [http://127.0.0.1:5001/chain](http://127.0.0.1:5001/chain)
```
* Expected Output: Your terminal will print a large JSON array of all the blocks in the chain, starting from the Genesis block. This is useful for verifying that a re-joined node has successfully synced.

## 7. Advanced Test 1: Node Re-join (New Port)
This test proves your Peer Discovery protocol works.

1. Kill a Node: Go to the terminal window for RS-4 (port 5004) and shut it down (press Ctrl+C).

2. Restart the Node on a NEW Port: Open a new, separate terminal and run the following command. This manually restarts RS-4 on port 5014:

```bash
python mbc_node.py -i RS-4 -p 5014 -b bootstrap1.hospital.net -b bootstrap2.hospital.net
```
3. Observe Logs:

   * The new RS-4 terminal will connect to a bootstrap, sync the chain, and then broadcast its new address.

   * All other running nodes (RS-1, RS-2, RS-3, RS-5) will print: ++ REGISTRY UPDATED: Node RS-4 is now at http://127.0.0.1:5014

   * This confirms the network has detected the node's new port.

## 8. Advanced Test 2: Bootstrap Failover & Chain Sync
This is the ultimate test of the network's High-Availability and Fork Resolution.

1. Kill Two Nodes:

   * Go to the terminal for RS-1 (Bootstrap 1) and shut it down (Ctrl+C).

   * Go to the terminal for RS-4 (Regular Node) and shut it down (Ctrl+C).

2. Restart RS-4: In a new, separate terminal, restart RS-4 on its original port:

```bash
python mbc_node.py -i RS-4 -p 5004 -b bootstrap1.hospital.net -b bootstrap2.hospital.net
```

3. Observe RS-4's Log: You will see the HA protocol in action:

   * `Contacting Bootstrap at bootstrap1.hospital.net...`

   * `!! Failed to connect to Bootstrap bootstrap1.hospital.net... (This is correct, it's down)`

   * `Contacting Bootstrap at bootstrap2.hospital.net...`

   * `++ Bootstrap Connection SUCCESSFUL with bootstrap2.hospital.net.`

   * `--- Proactively syncing chain with RS-2 ---`

   * `[Fork] Replacing local chain (length 1) with new chain... (This proves it is syncing the blocks it missed)`

   * `Broadcasting self registry entry...`

4. Propose a New Block: `RS-4`is now fully synced and back online. You can now propose a new block (using the curl command from Phase 3), and `RS-4` will correctly participate in the 5/5 consensus.