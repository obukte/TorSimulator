import unittest
import socket
import time
import json
from src.tor_simulator.node import Node


def find_free_port():
    s = socket.socket()
    s.bind(("", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestAutoCircuitFetch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start 10 relay nodes on random ports
        cls.relays = []
        cls.directory = []
        for i in range(10):
            port = find_free_port()
            node = Node(f"Relay{i}", host="127.0.0.1", port=port)
            # Start the relay listener and dummy sender
            node.start()
            time.sleep(0.1)  # give time for the server to begin listening
            cls.relays.append(node)
            cls.directory.append({
                'address': f"{node.host}:{node.port}",
                'host': node.host,
                'port': node.port
            })

        # Create a client node on its own port
        client_port = find_free_port()
        cls.client = Node("Client", host="127.0.0.1", port=client_port)
        # Ensure the auto-build method looks at the correct directory file
        cls.client.directory_file = 'nodes_directory.json'
        cls.directory.append({
            'address': f"{cls.client.host}:{cls.client.port}",
            'host': cls.client.host,
            'port': cls.client.port
        })

        # Write directory file
        with open('nodes_directory.json', 'w') as f:
            json.dump(cls.directory, f)

    def test_auto_build_and_fetch(self):
        # Attempt to build a 3-hop circuit
        circ_id = self.client.auto_build_random_circuit(hops_count=3, max_retries=5)
        self.assertIsNotNone(circ_id, "Auto-build circuit failed after retries")

        # Fetch data from a test web endpoint through the circuit
        result = self.client.fetch_url("http://httpbin.org/ip")
        # Expect the fetched JSON to contain the 'url' key
        self.assertIsInstance(result, dict)
        self.assertIn('url', result)


if __name__ == '__main__':
    unittest.main()
