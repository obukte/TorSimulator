# tests/test_local_fetch.py

import unittest
import threading
import socket
import json
import time
import os
from http.server import HTTPServer, SimpleHTTPRequestHandler

from src.tor_simulator.node import Node


def find_free_port():
    s = socket.socket()
    s.bind(("", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestLocalFetch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Ensure we're in the tests/ folder
        tests_dir = os.path.dirname(__file__)
        os.chdir(tests_dir)

        # Clean up any old directory file
        if os.path.exists("nodes_directory.json"):
            os.remove("nodes_directory.json")

        # Write a tiny JSON file to serve
        with open("test.json", "w") as f:
            json.dump({"message": "hello, world"}, f)

        # Start a local HTTP server
        cls.http_port = find_free_port()
        cls.httpd = HTTPServer(("127.0.0.1", cls.http_port), SimpleHTTPRequestHandler)
        cls.http_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.http_thread.start()

        # Spin up hops_count+1 relay nodes so client has enough peers
        hops_count = 3
        cls.nodes = []
        for i in range(hops_count + 1):
            port = find_free_port()
            node = Node(f"Relay{i}", host="127.0.0.1", port=port)
            node.start()
            cls.nodes.append(node)

        # Give them a moment to start
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def test_local_server_fetch(self):
        client = self.nodes[0]

        # Build a 3-hop circuit
        circ_id = client.auto_build_random_circuit(hops_count=3, max_retries=5)
        self.assertIsNotNone(circ_id, "Failed to build circuit")

        # Fetch the JSON over the onion circuit
        url = f"http://127.0.0.1:{self.http_port}/test.json"
        result = client.fetch_url(url)

        # Verify we got back our expected object (including URL)
        self.assertIsInstance(result, dict)
        expected = {"message": "hello, world", "url": url}
        self.assertEqual(result, expected)


if __name__ == "__main__":
    unittest.main()
