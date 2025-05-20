# Onion-Router Tor Simulator


A self-contained, educational onion-routing simulator that replicates Tor's core behavior—without a central directory authority or real Tor network. Instead, each relay **self-registers** by appending its address and port to a shared `nodes_directory.json` file, enabling clients to discover and connect to available relays dynamically. Circuits are built as three hops (Entry → Middle → Exit) using **ephemeral Diffie–Hellman** sessions over plain HTTP (no TLS); each hop derives an AES‑128 key via HKDF and applies one layer of onion encryption/decryption in fixed‑size 512‑byte cells.

Color‑coded console logging differentiates each node, making it easy to trace how data and control cells flow through the simulated network.


---

## Features

* 3‑hop circuits (Entry → Middle → Exit) with layered onion encryption.
* Ephemeral DH key exchange per hop, AES‑128 keys via HKDF.
* HTTP‑only transport (no TLS) for clarity and debuggability.
* Local directory file (`nodes_directory.json`) instead of a directory server.
* Timed  mixing mechanism batches and randomizes cell forwarding to provide basic traffic obfuscation.
* GUI and interactive CLI interfaces.

---

## 🔗 References

* **Tor Paper**: *"Tor: The Second-Generation Onion Router"* by Dingledine et al.
  [https://www.usenix.org/legacy/events/sec05/tech/full\_papers/dingledine/dingledine.pdf](https://www.usenix.org/legacy/events/sec05/tech/full_papers/dingledine/dingledine.pdf)

* **Tor Browser**: Official homepage & downloads.
  [https://www.torproject.org/projects/torbrowser.html](https://www.torproject.org/projects/torbrowser.html)

* **Batching & Mix Taxonomy**: Only the **timed flush** strategy is implemented.
  [https://www.freehaven.net/doc/batching-taxonomy/taxonomy.pdf](https://www.freehaven.net/doc/batching-taxonomy/taxonomy.pdf)

---

## Project Structure

```text
tor-simulator/
├── README.md                  ← This file
├── LICENSE
├── requirements.txt          ← Python dependencies (cryptography, requests)
├── pyproject.toml            ← Build & install metadata
│
├── src/                      ← Importable package
│   └── tor_simulator/        
│       ├── __init__.py
│       ├── cell.py           ← Tor cell format & parsing
│       ├── encryption_utils.py ← AES‑128 CBC + PKCS7 padding
│       ├── logger.py         ← Colorized console logging
│       └── node.py           ← Core Node class, DH handshakes, relay logic
│
├── scripts/                  ← Frontend launchers
│   ├── gui_circuit_builder.py       ← Tkinter GUI: start relays, pick hops, fetch a local message
│   └── interactive_circuit_builder.py ← CLI interactive builder: text-based selections
│
├── tests/                    ← Unit & integration tests
│   ├── test_circuit.py       ← 3‑hop build + HTTP fetch tests
│   └── test_local_fetch.py   ← Local HTTP server + onion fetch tests
```

---

## Class & Module Overview

### `cell.py`

* Defines constants and functions for Tor “cells” (fixed‑length 512‑byte frames).
* `create_cell(circ_id, cmd, payload)` packs header + payload into bytes.
* `parse_cell(data)` unpacks raw bytes into circuit ID, command, and payload.

### `encryption_utils.py`

* AES‑128 CBC encryption/decryption with PKCS7 padding.
* `encrypt(plaintext:  bytes, key: bytes) -> bytes`
* `decrypt(ciphertext: bytes, key: bytes) -> bytes`

### `logger.py`

* ANSI color definitions and `LogColors` enum.
* `colored_log(tag: str, msg: str, color: str)`: prints colorized, timestamped logs.

### `node.py` (Core)

Defines the **`Node`** class, which implements:

* **Registration**: appends its `host:port` to `nodes_directory.json` so clients can discover it.
* **Listener**: opens a TCP socket and parses incoming 512‑byte cells in a dedicated thread.
* **CREATE/CMD\_CREATED handler** (`_handle_create`): executes a DH handshake to derive the layer‑1 AES key.
* **RELAY\_EXTEND/RELAY\_EXTENDED handler** (`_handle_relay`): derives subsequent layer keys and forwards encrypted cells hop‑by‑hop.
* **`auto_build_random_circuit(hops_count: int, max_retries: int) -> int`**: builds an n‑hop circuit over a single connection by issuing CREATE and layered RELAY\_EXTEND.
* **`fetch_url(url: str) -> dict`**: sends an HTTP GET as `RELAY_DATA` cells through the circuit, reassembles and decrypts the response, and returns the parsed JSON.

### `gui_circuit_builder.py`

* **`CircuitBuilderApp`**: a Tkinter GUI that guides you through:

  1. **Start Nodes**: spin up X relays and register to the local file.
  2. **Select Hops**: choose exactly N relays for your circuit.
  3. **Fetch Message**: serve a user‑entered string via a temporary HTTP server and retrieve it through the onion circuit.

### `interactive_circuit_builder.py`

* A text‑based CLI that prompts in the terminal for # of hops and node selection, then fetches a local message via the built circuit.
---

##  Getting Started

From your project root:

**Install dependencies & editable package**

   ```sh
   pip install -r requirements.txt
   pip install -e .
   ```

**Interactive CLI circuit builder**

   ```sh
   python scripts/interactive_circuit_builder.py
   ```

   * Prompts you for the number of hops and relay selection in your terminal, then builds the circuit with those nodes while displaying color-coded logs.

**GUI circuit builder**

   ```sh
   python scripts/gui_circuit_builder.py
   ```

   * Spins up relay nodes, lets you pick the hops, and fetches a user-entered message from a local HTTP server over the established circuit.


---

## 📜 License

MIT © Omer Bukte
