import socket, threading, time, os, json, random, requests
from urllib.parse import urlparse
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from .cell import *
from .encryption_utils import EncryptionUtils
from .logger import colored_log, COLOR_LIST, LogColors

NODES_FILE = "nodes_directory.json"
TIMED_FLUSH_INTERVAL = 2.0

DH_PARAMETERS = None

def set_dh_parameters(params):
    global DH_PARAMETERS
    DH_PARAMETERS = params


def load_nodes():
    if os.path.exists(NODES_FILE):
        with open(NODES_FILE, "r") as f:
            try:
                return json.load(f)
            except Exception:
                return []
    return []


def save_node_info(info):
    nodes = load_nodes()
    if not any(n.get("address") == info.get("address") for n in nodes):
        nodes.append(info)
        with open(NODES_FILE, "w") as f:
            json.dump(nodes, f, indent=4)


def get_dh_parameters():
    pem_file = "dh_params.pem"
    if os.path.exists(pem_file):
        with open(pem_file, "rb") as f:
            params_pem = f.read()
        return serialization.load_pem_parameters(params_pem)
    else:
        params = dh.generate_parameters(generator=2, key_size=512)
        params_pem = params.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        )
        with open(pem_file, "wb") as f:
            f.write(params_pem)
        return params


# Initialize DH parameters when the module is loaded
set_dh_parameters(get_dh_parameters())


class Node:
    color_counter = 0

    def __init__(self, name, host='127.0.0.1', port=9001, logger=None, directory_file=NODES_FILE):
        self.name = name
        self.host = host
        self.port = port
        self.address = f"{host}:{port}"
        # Assign a color for logging
        if COLOR_LIST is None or not COLOR_LIST:
            self.color = LogColors.CYAN
        else:
             self.color = COLOR_LIST[Node.color_counter % len(COLOR_LIST)]
        Node.color_counter += 1
        # Setup logger
        self.logger = logger or (
            lambda action, msg: colored_log(f"[{self.address}][{action}]", msg, self.color))
        # Socket setup
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(5)
        # Node state
        self.dh_params = DH_PARAMETERS
        self.circuit_state = {}
        self.circuits = {}
        self.mix_queues = {}
        self.flush_threads = {}
        # Outgoing circuit specific state (client role)
        self._outgoing_hops = []
        self._outgoing_sock = None
        self._outgoing_keys = {}
        self._outgoing_id = None
        # Node directory info
        self.directory_file = directory_file
        self.available_nodes = self._load_nodes_internal()

    def _load_nodes_internal(self):
        """Internal method to load nodes from the specified file."""
        if os.path.exists(self.directory_file):
            try:
                with open(self.directory_file, "r") as f:
                    return json.load(f)
            except Exception as e:
                self.log("NODE_LOAD_ERROR", f"Failed to load nodes from {self.directory_file}: {e}")
                return []
        return []

    def log(self, action, msg):
        """Helper method for logging."""
        self.logger(action, msg)

    def start(self):
        """Starts the node's listening thread and saves its info."""
        self.log("START", f"Listening on {self.host}:{self.port} (Mix: timed)")
        threading.Thread(target=self._accept_loop, daemon=True).start()
        # Save own info to the directory file
        node_info = {"address": self.address, "host": self.host, "port": self.port, "node_id": self.name}
        current_nodes = self._load_nodes_internal()
        if not any(n.get("address") == self.address for n in current_nodes):
             current_nodes.append(node_info)
             try:
                 with open(self.directory_file, "w") as f:
                     json.dump(current_nodes, f, indent=4)
             except Exception as e:
                 self.log("NODE_SAVE_ERROR", f"Failed to save node info to {self.directory_file}: {e}")


    def _accept_loop(self):
        """Continuously accepts incoming connections."""
        while True:
            try:
                conn, addr = self.server.accept()
                self.log("ACCEPT", f"Accepted connection from {addr}")
                threading.Thread(target=self._handle_conn, args=(conn,), daemon=True).start()
            except Exception as e:
                self.log("ACCEPT_ERROR", f"Error accepting connections: {e}")
                time.sleep(1)


    def _handle_conn(self, conn):
        """Handles a single client connection, reading and processing cells."""
        data = b""
        peer_name = conn.getpeername()
        try:
            while True:
                chunk = conn.recv(CELL_SIZE * 8)
                if not chunk:
                    self.log("CONN_CLOSE", f"Connection closed by {peer_name}")
                    break
                data += chunk
                while len(data) >= CELL_SIZE:
                    cell = data[:CELL_SIZE]
                    data = data[CELL_SIZE:]
                    try:
                        self._handle_cell(cell, conn)
                    except Exception as e:
                        self.log("CELL_HANDLE_ERROR", f"Error processing cell from {peer_name}: {e}")
        except socket.error as e:
            self.log("CONN_ERROR", f"Socket error with {peer_name}: {e}")
        except Exception as e:
            self.log("CONN_ERROR", f"Unexpected error with {peer_name}: {type(e).__name__} - {e}")
        finally:
            conn.close()
            self._cleanup_circuits(conn)


    def _cleanup_circuits(self, conn):
        """Removes circuit state associated with a closed connection."""
        to_remove = [cid for cid, st in self.circuit_state.items()
                     if st.get('up') == conn or st.get('down') == conn]
        if to_remove:
            self.log("CLEANUP", f"Cleaning up circuits {to_remove} associated with connection {conn.getpeername()}")
            for cid in to_remove:
                self._remove_circuit(cid, notify_other_side=False)


    def _handle_cell(self, cell, conn):
        """Parses a cell and dispatches it to the appropriate handler."""
        try:
            cid, cmd, _, _, _, payload = parse_cell(cell)
            if cmd == CMD_CREATE:
                self._handle_create(cid, payload, conn)
            elif cmd == CMD_RELAY:
                self._handle_relay(cid, payload, conn)
            elif cmd == CMD_DESTROY:
                self.log("DESTROY", f"Received DESTROY for Circuit {cid} from {conn.getpeername()}")
                self._remove_circuit(cid)
            else:
                self.log("UNKNOWN_CMD", f"Received unknown command {cmd} for circuit {cid} from {conn.getpeername()}")
        except Exception as e:
            self.log("CELL_PARSE_ERROR", f"Failed to parse/handle cell from {conn.getpeername()}: {e}")


    def _handle_create(self, cid, payload, conn):
        """Handles a CMD_CREATE cell to establish a circuit hop."""
        self.log("CREATE", f"Processing CREATE for potential Circuit {cid} from {conn.getpeername()}")
        try:
            client_pub = serialization.load_pem_public_key(payload)
            priv = self.dh_params.generate_private_key()
            pub = priv.public_key()
            secret = priv.exchange(client_pub)
            key = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=b"demo").derive(secret) # AES-128 key

            self.circuit_state[cid] = {'key': key, 'up': conn, 'down': None}

            pub_pem = pub.public_bytes(encoding=serialization.Encoding.PEM,
                                       format=serialization.PublicFormat.SubjectPublicKeyInfo)
            conn.sendall(create_cell(cid, CMD_CREATED, pub_pem))
            self.log("CREATE", f"Circuit {cid} hop created (session key established with {conn.getpeername()})")
        except Exception as e:
            self.log("CREATE_ERROR", f"Failed to handle CREATE for circuit {cid}: {e}")
            # Should we send back an error cell? For now, just close conn implicitly by returning.


    def _send_upstream(self, cid, cell):
        """Queues a cell to be sent upstream with mixing/timing."""
        st = self.circuit_state.get(cid)
        if not st or not st.get('up'):
            self.log("SEND_UP_WARN", f"Cannot send upstream for circuit {cid}: No state or upstream connection.")
            return

        q = self.mix_queues.setdefault(cid, [])
        q.append(cell)
        if cid not in self.flush_threads or not self.flush_threads[cid].is_alive():
            t = threading.Thread(target=self._flusher, args=(cid,), daemon=True)
            self.flush_threads[cid] = t
            t.start()


    def _flusher(self, cid):
        """Periodically sends queued upstream cells with random shuffling."""
        time.sleep(TIMED_FLUSH_INTERVAL)
        cells_to_send = self.mix_queues.pop(cid, [])

        if not cells_to_send:
            self.flush_threads.pop(cid, None)
            return

        st = self.circuit_state.get(cid)
        if not st or not st.get('up'):
            self.flush_threads.pop(cid, None)
            return

        random.shuffle(cells_to_send)
        self.log("FLUSH", f"Flushing {len(cells_to_send)} cells upstream for circuit {cid}")
        upstream_conn = st['up']
        try:
            for cell in cells_to_send:
                upstream_conn.sendall(cell)
        except socket.error as e:
            self.log("FLUSH_ERROR", f"Socket error flushing circuit {cid}: {e}")
            self._remove_circuit(cid)
        finally:
            self.flush_threads.pop(cid, None)


    def _handle_relay(self, cid, payload, conn):
        """Handles CMD_RELAY cells, decrypting/encrypting and forwarding."""
        st = self.circuit_state.get(cid)
        if not st:
            self.log("RELAY_WARN", f"Circuit {cid} not found for incoming RELAY cell from {conn.getpeername()}.")
            return

        # Handling cell coming FROM UPSTREAM
        if conn is st.get('up'):
            source_desc = "UPSTREAM"
            dest_desc = "DOWNSTREAM"
            try:
                self.log("RELAY", f"CircID {cid}: Received encrypted cell FROM {source_desc} ({conn.getpeername()}).")
                data = EncryptionUtils.decrypt(payload, st['key'])
                sub = data[0]
                body = data[1:]
                self.log("RELAY", f"CircID {cid}: Decrypted {source_desc} cell. Sub-command: {sub}.")
                if st.get('down'):
                    downstream_conn = st['down']
                    self.log("RELAY", f"CircID {cid}: Forwarding cell TO {dest_desc} ({downstream_conn.getpeername()}) (Sub-command: {sub}).")
                    downstream_conn.sendall(create_cell(cid, CMD_RELAY, data))
                else:
                    self.log("RELAY", f"CircID {cid}: No downstream hop. Processing Sub-command {sub} locally.")
                    if sub == RELAY_EXTEND:
                        self._handle_extend(cid, body)
                    elif sub == RELAY_DATA:
                        self.log("RELAY", f"CircID {cid}: Acting as EXIT node for RELAY_DATA.")
                        self._handle_exit(cid, body, st['key'])
                    elif sub == RELAY_END:
                         self.log("RELAY_WARN", f"CircID {cid}: Received RELAY_END from {source_desc} but no downstream hop exists.")
                         self._remove_circuit(cid)
                    else:
                        self.log("RELAY_WARN", f"CircID {cid}: Unhandled relay sub-command {sub} from {source_desc}.")

            except Exception as e:
                self.log("RELAY_ERROR", f"CircID {cid}: Error processing {source_desc} cell: {type(e).__name__} - {e}")
                self._remove_circuit(cid)

        elif conn is st.get('down'):
             self.log("RELAY_WARN", f"CircID {cid}: _handle_relay called unexpectedly for DOWNSTREAM connection from {conn.getpeername()}. Should be handled by _relay_down.")
             try:
                 self.log("RELAY", f"CircID {cid}: Received cell FROM DOWNSTREAM (via _handle_relay).")
                 enc_payload = EncryptionUtils.encrypt(payload, st['key'])
                 self.log("RELAY", f"CircID {cid}: Encrypted DOWNSTREAM cell for UPSTREAM.")
                 self._send_upstream(cid, create_cell(cid, CMD_RELAY, enc_payload))
                 self.log("RELAY", f"CircID {cid}: Queued encrypted cell TO UPSTREAM.")
             except Exception as e:
                 self.log("RELAY_ERROR", f"CircID {cid}: Error processing DOWNSTREAM cell in _handle_relay: {e}")
                 self._remove_circuit(cid)
        else:
            self.log("RELAY_ERROR", f"CircID {cid}: Received RELAY cell from unrecognized connection {conn.getpeername()}. State: {st}")


    def _remove_circuit(self, cid, notify_other_side=True):
        """Removes a circuit and cleans up associated state and connections."""
        st = self.circuit_state.pop(cid, None)
        peer_up = None
        peer_down = None
        if st:
            self.log("REMOVE_CIRCUIT", f"Removing circuit {cid}.")
            upstream_conn = st.get('up')
            downstream_conn = st.get('down')

            if upstream_conn:
                peer_up = upstream_conn.getpeername() if upstream_conn.fileno() != -1 else None
                if notify_other_side:
                    try: upstream_conn.sendall(create_cell(cid, CMD_DESTROY, b'Teardown'))
                    except: pass
                try: upstream_conn.close()
                except: pass

            if downstream_conn:
                peer_down = downstream_conn.getpeername() if downstream_conn.fileno() != -1 else None
                if notify_other_side:
                    try: downstream_conn.sendall(create_cell(cid, CMD_DESTROY, b'Teardown'))
                    except: pass
                try: downstream_conn.close()
                except: pass

            self.log("REMOVE_CIRCUIT", f"Closed connections for circuit {cid}. Up: {peer_up}, Down: {peer_down}")

        self.mix_queues.pop(cid, None)
        flusher_thread = self.flush_threads.pop(cid, None)
        if flusher_thread and flusher_thread.is_alive():
            self.log("REMOVE_CIRCUIT", f"Flusher thread for circuit {cid} removed.")


    def _handle_extend(self, cid, data):
        """Handles a RELAY_EXTEND command to add the next hop to the circuit."""
        st = self.circuit_state.get(cid)
        if not st:
             self.log("RELAY_ERROR", f"CircID {cid}: State not found for RELAY_EXTEND.")
             return

        self.log("RELAY", f"CircID {cid}: Processing RELAY_EXTEND.")
        addr_str = "unknown"
        try:
            addr_bytes, key_pem = data.split(b"\n", 1)
            addr_str = addr_bytes.decode()
            host, port_str = addr_str.split(':')
            port = int(port_str)

            self.log("RELAY", f"CircID {cid}: Attempting to extend circuit TO {host}:{port}.")
            # Create a new connection to the next hop
            s = socket.create_connection((host, port), timeout=10)
            st['down'] = s
            self.log("RELAY", f"CircID {cid}: Successfully connected TO {host}:{port}.")

            create_payload = key_pem
            s.sendall(create_cell(cid, CMD_CREATE, create_payload))
            self.log("RELAY", f"CircID {cid}: Sent CREATE cell TO {host}:{port}.")

            s.settimeout(15.0)
            raw = s.recv(CELL_SIZE)
            s.settimeout(None)

            if not raw:
                raise ConnectionAbortedError(f"Connection to {host}:{port} closed before CREATED received.")

            _, cmd, *_, created_payload = parse_cell(raw)

            if cmd == CMD_CREATED:
                self.log("RELAY", f"CircID {cid}: Received CREATED cell FROM {host}:{port}.")
                extended_payload = created_payload
                sub_payload = bytes([RELAY_EXTENDED]) + extended_payload

                self.log("RELAY", f"CircID {cid}: Encrypting RELAY_EXTENDED for UPSTREAM.")
                enc_sub_payload = EncryptionUtils.encrypt(sub_payload, st['key'])
                self._send_upstream(cid, create_cell(cid, CMD_RELAY, enc_sub_payload))
                self.log("RELAY", f"CircID {cid}: Queued RELAY_EXTENDED TO UPSTREAM.")
                threading.Thread(target=self._relay_down, args=(cid, s), daemon=True).start()
                self.log("RELAY", f"CircID {cid}: Started _relay_down thread for {host}:{port}.")
            else:
                self.log("RELAY_ERROR", f"CircID {cid}: Expected CREATED (2) from {host}:{port}, got {cmd}. Closing extension.")
                s.close()
                st.pop('down', None)

        except socket.timeout:
             self.log("RELAY_ERROR", f"CircID {cid}: Timeout during RELAY_EXTEND to {addr_str}.")
             if 'down' in st and st.get('down'): st['down'].close()
             st.pop('down', None)
        except Exception as e:
            self.log("RELAY_ERROR", f"CircID {cid}: Failed during RELAY_EXTEND to {addr_str}: {type(e).__name__} - {e}")
            if 'down' in st and st.get('down'):
                try: st['down'].close()
                except: pass
                st.pop('down', None)


    # This method handles reading from the downstream socket and sending upstream
    def _relay_down(self, cid, downstream_sock):
        st = self.circuit_state.get(cid)
        source_desc = "DOWNSTREAM"
        dest_desc = "UPSTREAM"
        downstream_peer = downstream_sock.getpeername()

        if not st:
            self.log("RELAY_ERROR", f"CircID {cid}: Circuit state missing in _relay_down thread for {downstream_peer}.")
            try: downstream_sock.close()
            except: pass
            return # Exit thread if state is gone

        upstream_conn = st.get('up')
        if not upstream_conn:
            self.log("RELAY_ERROR", f"CircID {cid}: Upstream connection missing in _relay_down for {downstream_peer}.")
            try: downstream_sock.close()
            except: pass
            self._remove_circuit(cid, notify_other_side=False) # Cleanup circuit state
            return

        upstream_peer = upstream_conn.getpeername()
        self.log("RELAY", f"CircID {cid}: _relay_down thread started. Relaying {downstream_peer} -> {upstream_peer}.")

        try:
            while True:
                # Reading cell from downstream connection
                cell_data = downstream_sock.recv(CELL_SIZE)

                if not cell_data:
                    self.log("RELAY", f"CircID {cid}: {source_desc} connection ({downstream_peer}) closed.")
                    break # Exit loop if socket closed

                # Check if circuit still exists before processing
                if cid not in self.circuit_state:
                    self.log("RELAY_WARN", f"CircID {cid}: Circuit removed while _relay_down thread running for {downstream_peer}. Exiting.")
                    break

                # Parse cell received from downstream
                rec_cid, cmd, _, _, _, payload = parse_cell(cell_data)

                # Basic validation
                if rec_cid != cid:
                     self.log("RELAY_WARN", f"CircID {cid}: Received cell with mismatched circID {rec_cid} from {source_desc} ({downstream_peer}). Ignoring.")
                     continue # Ignore cell
                # Expecting RELAY or DESTROY from downstream
                if cmd not in [CMD_RELAY, CMD_DESTROY]:
                     self.log("RELAY_WARN", f"CircID {cid}: Received unexpected command {cmd} from {source_desc} ({downstream_peer}). Expecting RELAY or DESTROY.")
                     if cmd == CMD_DESTROY:
                          self.log("RELAY", f"CircID {cid}: Received DESTROY from {source_desc} ({downstream_peer}). Tearing down.")
                          break
                     continue

                self.log("RELAY", f"CircID {cid}: Received cell FROM {source_desc} ({downstream_peer}) (Cmd: {cmd}, Payload Size: {len(payload)}).")

                # Encrypt the payload with this node's layer key (shared with upstream)
                # The payload received here is already encrypted by downstream nodes
                enc_payload = EncryptionUtils.encrypt(payload, st['key'])
                self.log("RELAY", f"CircID {cid}: Encrypted {source_desc} cell payload for {dest_desc} ({upstream_peer}).")

                # Create the upstream cell and queue it for sending
                upstream_cell = create_cell(cid, CMD_RELAY, enc_payload)
                self._send_upstream(cid, upstream_cell)
                self.log("RELAY", f"CircID {cid}: Queued encrypted cell TO {dest_desc} ({upstream_peer}).")

        except socket.timeout:
             self.log("RELAY_ERROR", f"CircID {cid}: Socket timeout reading from {source_desc} ({downstream_peer}).")
        except socket.error as e:
            self.log("RELAY", f"CircID {cid}: Socket error reading from {source_desc} ({downstream_peer}): {e}.")
        except Exception as e:
            self.log("RELAY_ERROR", f"CircID {cid}: Unexpected error in _relay_down for {downstream_peer}: {type(e).__name__} - {e}")
        finally:
            self.log("RELAY", f"CircID {cid}: Exiting _relay_down thread for {downstream_peer}.")
            if cid in self.circuit_state:
                self._remove_circuit(cid)
            else:
                 try: downstream_sock.close()
                 except: pass


    def _handle_exit(self, cid, data, key):
        """Processes RELAY_DATA as the exit node: makes web request, sends response back."""
        st = self.circuit_state.get(cid)
        if not st:
            self.log("RELAY_EXIT_ERROR", f"CircID {cid}: State not found for RELAY_DATA exit processing.")
            return

        fetch_url = "unknown"
        try:
            # Decode the incoming request data
            req = data.decode(errors='ignore')
            self.log("RELAY_EXIT", f"CircID {cid}: Processing RELAY_DATA as EXIT node. Decoded Request (first 500 chars):\n{req[:500]}")

            # Basic parsing to find target URL
            lines = req.split('\r\n')
            if not lines:
                 self.log("RELAY_EXIT_ERROR", f"CircID {cid}: Received empty RELAY_DATA request.")
                 raise ValueError("Empty request")

            parts = lines[0].split(' ')
            if len(parts) < 2:
                 self.log("RELAY_EXIT_ERROR", f"CircID {cid}: Malformed request line: {lines[0]}")
                 raise ValueError("Malformed request line")

            target_path = parts[1]

            host_line = next((l for l in lines if l.lower().startswith('host:')), None)

            if target_path.startswith(('http://', 'https://')):
                fetch_url = target_path
            elif host_line:
                host = host_line.split(':', 1)[1].strip()
                fetch_url = f"http://{host}{target_path}"
            else:
                self.log("RELAY_EXIT_ERROR", f"CircID {cid}: Cannot determine target host from request headers.")
                raise ValueError("Cannot determine host")

            self.log("RELAY_EXIT", f"CircID {cid}: Making outgoing web request via requests library to: {fetch_url}")

            try:
                resp = requests.get(fetch_url, timeout=20, verify=False, allow_redirects=True)
                resp.raise_for_status()
                self.log("RELAY_EXIT", f"CircID {cid}: Received response status {resp.status_code} from {fetch_url}")
                response_body = resp.content
            except requests.exceptions.RequestException as req_err:
                 self.log("RELAY_EXIT_ERROR", f"CircID {cid}: External request failed for {fetch_url}: {req_err}")
                 response_body = b""


            # Process and send response body chunks
            self.log("RELAY_EXIT", f"CircID {cid}: Sending {len(response_body)} bytes of response body back into circuit.")
            max_inner_payload = MAX_PAYLOAD_SIZE - 1
            chunks = [response_body[i:i + max_inner_payload] for i in range(0, len(response_body), max_inner_payload)]

            for i, chunk in enumerate(chunks):
                # Wrap chunk in RELAY_DATA sub-command
                inner_payload = bytes([RELAY_DATA]) + chunk
                # Encrypt with the key shared with the previous* hop
                enc_payload = EncryptionUtils.encrypt(inner_payload, key)
                # Queue the cell for sending upstream
                self._send_upstream(cid, create_cell(cid, CMD_RELAY, enc_payload))
                # Log progress without being too verbose
                if i % 10 == 0 or i == len(chunks) - 1:
                     self.log("RELAY_EXIT", f"CircID {cid}: Queued response chunk {i+1}/{len(chunks)} upstream.")


            # Send RELAY_END cell to signify end of data stream
            self.log("RELAY_EXIT", f"CircID {cid}: Sending RELAY_END back into circuit.")
            end_payload = bytes([RELAY_END]) # Empty body for RELAY_END
            enc_end_payload = EncryptionUtils.encrypt(end_payload, key)
            self._send_upstream(cid, create_cell(cid, CMD_RELAY, enc_end_payload))
            self.log("RELAY_EXIT", f"CircID {cid}: Queued RELAY_END upstream.")

        except ValueError as val_err:
             self.log("RELAY_EXIT_ERROR", f"CircID {cid}: Invalid request data: {val_err}")
             end_payload = bytes([RELAY_END])
             enc_end_payload = EncryptionUtils.encrypt(end_payload, key)
             self._send_upstream(cid, create_cell(cid, CMD_RELAY, enc_end_payload))
        except Exception as e:
            self.log("RELAY_EXIT_ERROR", f"CircID {cid}: Error during exit processing for {fetch_url}: {type(e).__name__} - {e}")
            end_payload = bytes([RELAY_END])
            enc_end_payload = EncryptionUtils.encrypt(end_payload, key)
            self._send_upstream(cid, create_cell(cid, CMD_RELAY, enc_end_payload))
            self.log("RELAY_EXIT", f"CircID {cid}: Queued RELAY_END upstream after generic error.")


    def build_outgoing_circuit(self, hops):
        """Builds a new circuit initiated by this node (client role)."""
        if self._outgoing_sock:
            self.log("BUILD_CIRCUIT", "Destroying existing outgoing circuit before building new one.")
            self.destroy_outgoing_circuit() # Ensure no old circuit is active

        if not hops:
            self.log("BUILD_CIRCUIT_ERROR", "No hops provided.")
            return None

        self._outgoing_hops = hops
        self._outgoing_keys = {}
        self._outgoing_id = random.randint(1, 0xFFFF)
        self.log("BUILD_CIRCUIT", f"Attempting to build {len(hops)}-hop circuit with ID {self._outgoing_id}.")
        self.log("BUILD_CIRCUIT", f"Path: {' -> '.join(h['address'] for h in hops)}")

        current_connection = None
        try:
            # Connect to Entry Node
            entry_hop = hops[0]
            self.log("BUILD_CIRCUIT", f"Connecting to entry node {entry_hop['address']}...")
            s = socket.create_connection((entry_hop["host"], entry_hop["port"]), timeout=10)
            current_connection = s
            self._outgoing_sock = s
            self.log("BUILD_CIRCUIT", f"Connected to entry node {entry_hop['address']}.")

            # DH Key Exchange with Entry Node
            self.log("BUILD_CIRCUIT", f"Performing DH exchange with {entry_hop['address']}...")
            priv = self.dh_params.generate_private_key()
            pub_pem = priv.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            # Send CREATE cell with our public key
            s.sendall(create_cell(self._outgoing_id, CMD_CREATE, pub_pem))
            self.log("BUILD_CIRCUIT", f"Sent CREATE cell to {entry_hop['address']}.")

            # Receive CREATED cell from entry node
            s.settimeout(15.0)
            raw = s.recv(CELL_SIZE)
            s.settimeout(None)
            if not raw: raise ConnectionAbortedError("Entry node closed connection before sending CREATED.")

            rec_cid, cmd, _, _, _, created_payload = parse_cell(raw)
            if cmd != CMD_CREATED or rec_cid != self._outgoing_id:
                 self.log("BUILD_CIRCUIT_ERROR", f"Expected CREATED for {self._outgoing_id} from {entry_hop['address']}, got cmd {cmd} cid {rec_cid}.")
                 raise ValueError("Invalid CREATED response from entry node.")

            self.log("BUILD_CIRCUIT", f"Received CREATED cell from {entry_hop['address']}.")
            # Derive shared key with entry node
            peer_pub = serialization.load_pem_public_key(created_payload)
            secret = priv.exchange(peer_pub)
            self._outgoing_keys[1] = HKDF(
                algorithm=hashes.SHA256(), length=16, salt=None, info=b"demo"
            ).derive(secret)
            self.log("BUILD_CIRCUIT", f"Derived shared key with entry node {entry_hop['address']}.")

            # Extend to Middle/Exit Nodes
            for i, next_hop in enumerate(hops[1:], start=2):
                current_hop_index = i
                prev_hop_address = hops[current_hop_index-2]['address']
                next_hop_address = next_hop['address']
                self.log("BUILD_CIRCUIT", f"Extending circuit from {prev_hop_address} TO {next_hop_address} (Hop {current_hop_index}).")

                # DH key exchange setup for the next hop
                priv_extend = self.dh_params.generate_private_key()
                pub_extend_pem = priv_extend.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )

                extend_payload = (
                        f"{next_hop['host']}:{next_hop['port']}\n".encode()
                        + pub_extend_pem
                )
                relay_payload_inner = bytes([RELAY_EXTEND]) + extend_payload

                encrypted_relay_payload = relay_payload_inner
                for layer_index in range(current_hop_index - 1, 0, -1):
                    key_for_layer = self._outgoing_keys[layer_index]
                    encrypted_relay_payload = EncryptionUtils.encrypt(encrypted_relay_payload, key_for_layer)
                    self.log("BUILD_CIRCUIT_DEBUG", f"Encrypted EXTEND for layer {layer_index}")


                self.log("BUILD_CIRCUIT", f"Sending encrypted RELAY_EXTEND for {next_hop_address} via entry node.")
                s.sendall(create_cell(self._outgoing_id, CMD_RELAY, encrypted_relay_payload))

                self.log("BUILD_CIRCUIT", f"Waiting for RELAY_EXTENDED response from {next_hop_address}...")
                extended_received = False
                while not extended_received:
                    s.settimeout(20.0)
                    raw_response = s.recv(CELL_SIZE)
                    s.settimeout(None)
                    if not raw_response: raise ConnectionAbortedError("Connection closed while waiting for RELAY_EXTENDED.")

                    rec_cid_ext, cmd_ext, _, _, _, payload_ext = parse_cell(raw_response)

                    if rec_cid_ext != self._outgoing_id:
                         self.log("BUILD_CIRCUIT_WARN", f"Received cell for wrong circuit {rec_cid_ext} while waiting for RELAY_EXTENDED.")
                         continue

                    if cmd_ext == CMD_DESTROY:
                         self.log("BUILD_CIRCUIT_ERROR", f"Received DESTROY cell while waiting for RELAY_EXTENDED from {next_hop_address}.")
                         raise ValueError("Circuit destroyed during extension.")

                    if cmd_ext != CMD_RELAY:
                         self.log("BUILD_CIRCUIT_WARN", f"Expected RELAY command (for EXTENDED), got {cmd_ext}. Ignoring.")
                         continue

                    decrypted_payload = payload_ext
                    try:
                        for layer_index in range(1, current_hop_index):
                             key_for_layer = self._outgoing_keys[layer_index]
                             decrypted_payload = EncryptionUtils.decrypt(decrypted_payload, key_for_layer)
                             self.log("BUILD_CIRCUIT_DEBUG", f"Decrypted EXTENDED response layer {layer_index}")
                    except Exception as decrypt_err:
                         self.log("BUILD_CIRCUIT_ERROR", f"Failed to decrypt RELAY_EXTENDED response: {decrypt_err}")
                         raise ValueError("Decryption failed for RELAY_EXTENDED")

                    # Process the decrypted payload
                    sub_command = decrypted_payload[0]
                    sub_body = decrypted_payload[1:]

                    if sub_command == RELAY_EXTENDED:
                        self.log("BUILD_CIRCUIT", f"Successfully received and decrypted RELAY_EXTENDED from {next_hop_address}.")
                        next_hop_pub_key = serialization.load_pem_public_key(sub_body)
                        secret_extend = priv_extend.exchange(next_hop_pub_key)
                        self._outgoing_keys[current_hop_index] = HKDF(
                            algorithm=hashes.SHA256(),
                            length=16,
                            salt=None,
                            info=b"demo",
                        ).derive(secret_extend)
                        self.log("BUILD_CIRCUIT", f"Derived shared key with {next_hop_address} (Hop {current_hop_index}).")
                        extended_received = True
                    else:
                        self.log("BUILD_CIRCUIT_WARN", f"Expected RELAY_EXTENDED (2), got sub-command {sub_command}. Ignoring.")

            # Circuit Built Successfully
            self.log("BUILD_CIRCUIT", f"Successfully built {len(hops)}-hop circuit {self._outgoing_id}.")

            msg_lines = [f"[{self.address}][-----CIRCUIT---CREATED]",
                         f"Entry Node:  {hops[0]['address']}"]
            if len(hops) > 2:
                for idx, hop in enumerate(hops[1:-1], 1):
                    msg_lines.append(f"Middle Node {idx}: {hop['address']}")
            msg_lines.append(f"Exit  Node:  {hops[-1]['address']}")
            self.log("INFO", "\n".join(msg_lines))

            # Store basic info about the outgoing circuit
            self.circuits[self._outgoing_id] = {
                "path": hops,
            }
            return self._outgoing_id

        except (socket.error, socket.timeout, ConnectionAbortedError, ValueError, KeyError, serialization.UnsupportedAlgorithm, Exception) as e:
            self.log("BUILD_CIRCUIT_ERROR", f"Circuit build failed: {type(e).__name__} - {e}")
            if current_connection:
                try:
                    if self._outgoing_id and current_connection.fileno() != -1:
                        current_connection.sendall(create_cell(self._outgoing_id, CMD_DESTROY, b'Build failed'))
                    current_connection.close()
                except: pass
            self._outgoing_sock = None
            self._outgoing_hops = []
            self._outgoing_keys = {}
            self._outgoing_id = None
            return None


    def auto_build_random_circuit(self, hops_count=3, max_retries=5):
        """Automatically selects random nodes and attempts to build a circuit."""
        self.log("AUTO_BUILD", f"Attempting to auto-build a {hops_count}-hop circuit...")
        try:
            nodes = self._load_nodes_internal()
        except Exception as e:
            self.log("AUTO_BUILD_ERROR", f"Failed to load node directory: {e}")
            return None

        candidates = [
            n for n in nodes
            if n.get('address') != self.address
        ]

        if len(candidates) < hops_count:
            self.log("AUTO_BUILD_ERROR", f"Not enough candidate nodes ({len(candidates)}) available to build a {hops_count}-hop circuit.")
            return None

        self.log("AUTO_BUILD", f"Found {len(candidates)} candidate nodes.")

        for attempt in range(max_retries):
            self.log("AUTO_BUILD", f"Attempt {attempt + 1}/{max_retries}...")
            try:
                hops = random.sample(candidates, hops_count)
                circ_id = self.build_outgoing_circuit(hops)
                if circ_id:
                    self.log("AUTO_BUILD", f"Successfully built circuit {circ_id} on attempt {attempt + 1}.")
                    return circ_id
                else:
                    self.log("AUTO_BUILD_WARN", f"Circuit build attempt {attempt + 1} failed.")
            except ValueError:
                 self.log("AUTO_BUILD_ERROR", "Cannot select hops, sample size issue.")
                 return None
            except Exception as e:
                self.log("AUTO_BUILD_ERROR", f"Unexpected error during attempt {attempt + 1}: {e}")
                # Continue to next attempt

        self.log("AUTO_BUILD_ERROR", f"Failed to build circuit after {max_retries} attempts.")
        return None

    def send_data_through_outgoing_circuit(self, data):
        """Sends application data through the established outgoing circuit."""
        if not self._outgoing_sock:
            self.log("SEND_DATA_ERROR", "No outgoing socket available.")
            return None
        if not self._outgoing_id or not self._outgoing_keys or not self._outgoing_hops:
            self.log("SEND_DATA_ERROR", "Outgoing circuit ID, keys, or hops missing.")
            return None

        self.log("SEND_DATA", f"Sending {len(data)} bytes of application data via circuit {self._outgoing_id}.")
        try:
            payload = bytes([RELAY_DATA]) + data

            encrypted_payload = payload
            for i in range(len(self._outgoing_hops), 0, -1):
                if i not in self._outgoing_keys:
                    self.log("SEND_DATA_ERROR", f"Missing encryption key for hop {i} during send.")
                    self.destroy_outgoing_circuit()
                    return None
                key = self._outgoing_keys[i]
                encrypted_payload = EncryptionUtils.encrypt(encrypted_payload, key)

            self.log("SEND_DATA",
                     f"Sending RELAY_DATA cell (encrypted size: {len(encrypted_payload)}) for circID {self._outgoing_id}.")
            self._outgoing_sock.sendall(create_cell(self._outgoing_id, CMD_RELAY, encrypted_payload))

            # Receive Response
            full_response = b""
            self.log("SEND_DATA", "Waiting for response cells from circuit...")

            while True:
                self._outgoing_sock.settimeout(30.0)
                try:
                    raw_response_cell = self._outgoing_sock.recv(CELL_SIZE)
                except socket.timeout:
                    self.log("SEND_DATA_ERROR",
                             "Socket timed out waiting for response cell. Assuming incomplete response.")
                    self.destroy_outgoing_circuit()
                    return None
                finally:
                    self._outgoing_sock.settimeout(None)

                if not raw_response_cell:
                    self.log("SEND_DATA_ERROR", "Socket connection broken while receiving response.")
                    self.destroy_outgoing_circuit()
                    return None

                # Parse and Decrypt Received Cell
                rec_cid, cmd, _, _, _, enc_payload_resp = parse_cell(raw_response_cell)

                if rec_cid != self._outgoing_id:
                    self.log("SEND_DATA_WARN", f"Received cell for wrong circuit {rec_cid}. Ignoring.")
                    continue
                if cmd == CMD_DESTROY:
                    self.log("SEND_DATA_ERROR", f"Received DESTROY cell for circuit {self._outgoing_id}. Aborting.")
                    self.destroy_outgoing_circuit()
                    return None
                if cmd != CMD_RELAY:
                    self.log("SEND_DATA_WARN",
                             f"Received unexpected command {cmd} instead of RELAY. Stopping response read.")
                    break

                self.log("SEND_DATA_RECV", f"Received RELAY cell, payload length: {len(enc_payload_resp)}")

                # Decrypt layers (peeling the onion)
                decrypted_payload_resp = enc_payload_resp
                try:
                    # Decrypt starting from entry node (hop 1) up to exit node (hop N)
                    for i in range(1, len(self._outgoing_hops) + 1):
                        # Ensure the key exists before trying to use it
                        if i not in self._outgoing_keys:
                            self.log("SEND_DATA_ERROR", f"Missing decryption key for hop {i} during receive.")
                            self.destroy_outgoing_circuit()
                            return None
                        key = self._outgoing_keys[i]
                        decrypted_payload_resp = EncryptionUtils.decrypt(decrypted_payload_resp, key)
                except Exception as decrypt_err:
                    self.log("SEND_DATA_ERROR", f"Failed to decrypt response cell: {decrypt_err}")
                    self.destroy_outgoing_circuit()
                    return None

                # Process Decrypted Payload
                if not decrypted_payload_resp:
                    self.log("SEND_DATA_WARN", "Received empty decrypted payload in RELAY cell. Ignoring.")
                    continue

                sub_command = decrypted_payload_resp[0]
                body = decrypted_payload_resp[1:]
                self.log("SEND_DATA_RECV",
                         f"Decrypted relay cell, sub-command: {sub_command}, body length: {len(body)}")

                should_break = False
                if sub_command == RELAY_DATA:
                    full_response += body
                    self.log("SEND_DATA_RECV",
                             f"Appended {len(body)} bytes to response. Total size now: {len(full_response)}")
                elif sub_command == RELAY_END:
                    self.log("SEND_DATA_RECV", "Received RELAY_END cell. Response complete.")
                    should_break = True
                else:
                    self.log("SEND_DATA_WARN",
                             f"Received unexpected relay sub-command {sub_command}. Stopping response read.")
                    should_break = True

                if should_break:
                    break

            self.log("SEND_DATA", f"Finished receiving response. Total size: {len(full_response)} bytes.")
            return full_response

        except socket.timeout:
            self.log("SEND_DATA_ERROR", "Socket timed out during send operation.")
            self.destroy_outgoing_circuit()
            return None
        except socket.error as sock_err:
            self.log("SEND_DATA_ERROR", f"Socket error during send/recv: {sock_err}")
            self.destroy_outgoing_circuit()
            return None
        except KeyError as key_err:
            self.log("SEND_DATA_ERROR",
                     f"Missing key during encryption/decryption for hop {key_err}. Circuit state issue?")
            self.destroy_outgoing_circuit()
            return None
        except Exception as e:
            self.log("SEND_DATA_ERROR", f"Unexpected error in send_data: {type(e).__name__} - {e}")
            self.destroy_outgoing_circuit()
            return None


    def destroy_outgoing_circuit(self):
        """Destroys the currently active outgoing circuit."""
        if self._outgoing_sock and self._outgoing_id is not None:
            self.log("DESTROY_OUTGOING", f"Destroying outgoing circuit {self._outgoing_id}")
            try:
                self._outgoing_sock.sendall(create_cell(self._outgoing_id, CMD_DESTROY, b"Client shutdown"))
            except socket.error as e:
                 self.log("DESTROY_OUTGOING_WARN", f"Socket error sending DESTROY cell: {e}. May already be closed.")
            except Exception as e:
                 self.log("DESTROY_OUTGOING_WARN", f"Error sending DESTROY cell: {e}")

            # Close the socket
            try:
                self._outgoing_sock.close()
            except socket.error as e:
                self.log("DESTROY_OUTGOING_WARN", f"Error closing outgoing socket: {e}. May already be closed.")

        if self._outgoing_id in self.circuits:
             del self.circuits[self._outgoing_id]
        self._outgoing_sock = None
        self._outgoing_hops = []
        self._outgoing_keys = {}
        self._outgoing_id = None
        self.log("DESTROY_OUTGOING", "Outgoing circuit state cleared.")


    def get_available_nodes(self):
        """Returns the list of currently known available nodes."""
        return self.available_nodes


    def fetch_url(self, url):
        """Fetches a URL through the established outgoing circuit."""
        self.log("FETCH_URL", f"Attempting to fetch URL: {url} via circuit {self._outgoing_id}")

        # Check if circuit is ready
        if not self._outgoing_sock:
            self.log("FETCH_URL_ERROR", "Outgoing socket is not available. Build circuit first.")
            return None
        if not self._outgoing_id:
            self.log("FETCH_URL_ERROR", "Outgoing circuit ID is not set. Build circuit first.")
            return None

        response_bytes = None
        try:
            parsed_url = urlparse(url)
            host = parsed_url.netloc
            path = parsed_url.path if parsed_url.path else "/"
            if not host:
                 self.log("FETCH_URL_ERROR", f"Could not parse host from URL: {url}")
                 return None

            request_lines = [
                f"GET {path} HTTP/1.1",
                f"Host: {host}",
                "Connection: close",
                "Accept: */*",
                "\r\n"
            ]
            http_request = "\r\n".join(request_lines).encode('utf-8')

            self.log("FETCH_URL_SEND", f"Sending request via circuit {self._outgoing_id}:\n{http_request.decode().strip()}")

            # Send Request and Receive Response via Circuit
            response_bytes = self.send_data_through_outgoing_circuit(http_request)

            if response_bytes is None:
                self.log("FETCH_URL_ERROR", "Failed to get response through circuit.")
                return None
            else:
                self.log("FETCH_URL_RECV", f"Received {len(response_bytes)} bytes in total response via circuit {self._outgoing_id}.")
                try:
                     preview = response_bytes[:500].decode('utf-8', errors='replace')
                except Exception as decode_err:
                     preview = f"(Error decoding preview: {decode_err}) Raw: {response_bytes[:500]}"
                self.log("FETCH_URL_RECV_PREVIEW", f"Response preview (first 500 bytes):\n---\n{preview}\n---")

        except socket.error as sock_err:
            self.log("FETCH_URL_ERROR", f"Socket error during fetch prep/call: {sock_err}")
            self.destroy_outgoing_circuit()
            return None
        except Exception as e:
            self.log("FETCH_URL_ERROR", f"Unexpected error during request preparation phase: {type(e).__name__} - {e}")
            self.destroy_outgoing_circuit()
            return None


        # Process the Received Response
        try:
            self.log("FETCH_URL_PROC", "Attempting to decode response as UTF-8...")
            text = response_bytes.decode('utf-8', errors='ignore')
            self.log("FETCH_URL_PROC", f"Successfully decoded response (length: {len(text)}).")

            start = text.find('{')
            end = text.rfind('}') + 1

            if start == -1 or end == 0:
                self.log("FETCH_URL_PROC_ERROR", "Could not find JSON object markers '{' and '}' in response.")
                self.log("FETCH_URL_PROC_TEXT_DEBUG", f"Received text (first 1000 chars):\n---\n{text[:1000]}\n---")
                return None
            else:
                 self.log("FETCH_URL_PROC", f"Found potential JSON block from index {start} to {end}.")

            json_text = text[start:end]
            self.log("FETCH_URL_PROC", f"Attempting to parse JSON text: {json_text[:200]}...")
            data = json.loads(json_text)
            self.log("FETCH_URL_PROC", "Successfully parsed JSON response.")

        except json.JSONDecodeError as json_err:
            self.log("FETCH_URL_PROC_ERROR", f"JSON decoding failed: {json_err}")
            self.log("FETCH_URL_PROC_ERROR_TEXT", f"Text attempted to parse (first 500 chars): {json_text[:500]}")
            return None
        except Exception as e:
            self.log("FETCH_URL_PROC_ERROR", f"Unexpected error during response processing: {type(e).__name__} - {e}")
            if response_bytes:
                 self.log("FETCH_URL_PROC_RAW_DEBUG", f"Raw response bytes on error (first 500): {response_bytes[:500]}")
            return None

        data['url'] = url
        self.log("FETCH_URL_SUCCESS", f"Successfully fetched and parsed JSON from {url}.")
        return data