import socket
import time
import os
import sys
from tor_simulator.node import Node, set_dh_parameters, get_dh_parameters

NODES_DIRECTORY_FILE = "../tests/nodes_directory.json"

def find_free_port():
    """Finds an available port on the local machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    port = s.getsockname()[1]
    s.close()
    return port

def clear_directory_file():
    """Clears the node directory file."""
    if os.path.exists(NODES_DIRECTORY_FILE):
        try:
            os.remove(NODES_DIRECTORY_FILE)
            print(f"Cleared existing directory file: {NODES_DIRECTORY_FILE}")
        except OSError as e:
            print(f"Warning: Could not clear directory file {NODES_DIRECTORY_FILE}: {e}")

def start_node(node_name, host="127.0.0.1", port=None, directory_file=NODES_DIRECTORY_FILE):
    """Starts a single node instance."""
    if port is None:
        port = find_free_port()
    node = Node(node_name, host=host, port=port, directory_file=directory_file)
    node.start()
    time.sleep(0.2)
    return node

def display_nodes(node_list):
    """Displays a numbered list of nodes."""
    print("\nAvailable Relay Nodes:")
    if not node_list:
        print("  No relay nodes available.")
        return
    for i, node_info in enumerate(node_list):
        print(f"  [{i}] {node_info.get('address', 'Unknown Address')} (Name: {node_info.get('node_id', 'Unknown')})")

def get_int_input(prompt, min_val=None, max_val=None):
    """Gets and validates integer input from the user."""
    while True:
        try:
            value = int(input(prompt).strip())
            if min_val is not None and value < min_val:
                print(f"  Error: Value must be at least {min_val}.")
            elif max_val is not None and value > max_val:
                print(f"  Error: Value must be no more than {max_val}.")
            else:
                return value
        except ValueError:
            print("  Error: Please enter a valid integer.")

def main():
    """Main function to run the interactive circuit builder."""
    print("--- Interactive Tor Circuit Builder ---")
    try:
        set_dh_parameters(get_dh_parameters())
    except Exception as e:
        print(f"Error initializing DH parameters: {e}")
        sys.exit(1)
    clear_directory_file()

    num_relays = get_int_input("How many relay nodes to start? ", min_val=1)
    hops_count = get_int_input(f"How many hops for the circuit (e.g., 3)? ", min_val=1, max_val=num_relays)

    print(f"\nStarting {num_relays} relay nodes and 1 client node...")
    relay_nodes = []
    all_node_objects = []

    for i in range(num_relays):
        node_name = f"Relay-{i+1}"
        try:
            relay_node = start_node(node_name, directory_file=NODES_DIRECTORY_FILE)
            relay_nodes.append(relay_node)
            all_node_objects.append(relay_node)
            print(f"  Started {node_name} on {relay_node.address}")
        except Exception as e:
            print(f"  Error starting {node_name}: {e}")

    try:
        client_node = start_node("Client-Node", directory_file=NODES_DIRECTORY_FILE)
        all_node_objects.append(client_node)
        print(f"  Started Client-Node on {client_node.address}")
    except Exception as e:
        print(f"  Error starting Client-Node: {e}")
        print("Cannot proceed without a client node. Exiting.")
        sys.exit(1)

    print("\nAll nodes started.")

    available_relays_info = [n for n in client_node._load_nodes_internal() if n['address'] != client_node.address]

    if len(available_relays_info) < hops_count:
         print(f"\nError: Not enough relay nodes ({len(available_relays_info)}) available to build a {hops_count}-hop circuit.")
         sys.exit(1)

    display_nodes(available_relays_info)

    selected_hops_info = []
    selected_indices = set()
    hop_names = ["Entry"] + [f"Middle-{i+1}" for i in range(hops_count - 2)] + ["Exit"] if hops_count > 1 else ["Entry/Exit"]

    print(f"\nPlease select {hops_count} distinct relay nodes by index for the circuit path:")
    for i in range(hops_count):
        prompt = f"  Choose index for {hop_names[i]} node: "
        while True:
            index = get_int_input(prompt, min_val=0, max_val=len(available_relays_info) - 1)
            if index in selected_indices:
                print(f"  Error: Node at index {index} already selected. Please choose a different node.")
            else:
                selected_indices.add(index)
                selected_hops_info.append(available_relays_info[index])
                break

    print("\nSelected path:")
    for i, hop in enumerate(selected_hops_info):
        print(f"  Hop {i+1} ({hop_names[i]}): {hop['address']}")

    print("\nAttempting to build the circuit using the selected path...")
    time.sleep(1)

    circuit_id = client_node.build_outgoing_circuit(selected_hops_info)

    if circuit_id:
        print(f"\nSUCCESS: Circuit built successfully!")
        print(f"  Circuit ID: {circuit_id}")
        print(f"  Path:")
        final_path = client_node._outgoing_hops
        for i, hop in enumerate(final_path):
             print(f"    Hop {i+1} ({hop_names[i]}): {hop['address']}")
    else:
        print("\nFAILURE: Failed to build the circuit.")
        print("  Check the logs of the client and relay nodes for errors.")

    print("\nNodes are running. Press Ctrl+C to exit.")
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print("\nExiting...")

if __name__ == "__main__":
    main()