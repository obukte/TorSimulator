import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
import threading
import socket
import time
import os
import queue
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from tor_simulator.node import Node

NODES_DIRECTORY_FILE = "nodes_directory.json"

def find_free_port():
    s = socket.socket()
    s.bind(("", 0))
    port = s.getsockname()[1]
    s.close()
    return port

def clear_directory_file():
    if os.path.exists(NODES_DIRECTORY_FILE):
        try: os.remove(NODES_DIRECTORY_FILE)
        except OSError: pass

class CircuitBuilderApp:
    def __init__(self, root):
        self.root = root
        root.title("Tor Simulator GUI")
        root.geometry("700x700")

        # Internal state
        self.relay_nodes_info = []
        self.all_node_objects = []
        self.selected_hops = []
        self.client_node = None
        self.num_hops_required = 0
        self.current_circuit_id = None
        self.update_queue = queue.Queue()

        self.create_widgets()
        self.check_queue()
        self.set_ui_state('initial')

    def create_widgets(self):
        cfg = ttk.LabelFrame(self.root, text="1. Configuration", padding=10)
        cfg.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(cfg, text="# Relays:").grid(row=0, column=0)
        self.relays_var = tk.IntVar(value=4)
        ttk.Entry(cfg, textvariable=self.relays_var, width=5).grid(row=0, column=1)
        ttk.Label(cfg, text="# Hops:").grid(row=0, column=2)
        self.hops_var = tk.IntVar(value=3)
        ttk.Entry(cfg, textvariable=self.hops_var, width=5).grid(row=0, column=3)
        self.start_btn = ttk.Button(cfg, text="Start Nodes", command=self.start_nodes_thread)
        self.start_btn.grid(row=0, column=4, padx=10)

        # Node selection frame
        sel = ttk.LabelFrame(self.root, text="2. Node Selection", padding=10)
        sel.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.prompt_label = ttk.Label(sel, text="Start nodes to see relays.")
        self.prompt_label.pack(anchor=tk.W)
        frm = ttk.Frame(sel)
        frm.pack(fill=tk.BOTH, expand=True)
        self.node_listbox = tk.Listbox(frm, selectmode=tk.SINGLE, height=8,
                                       bg='white', fg='black',
                                       selectbackground='lightblue', selectforeground='black')
        self.node_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb = ttk.Scrollbar(frm, orient=tk.VERTICAL, command=self.node_listbox.yview)
        sb.pack(side=tk.LEFT, fill=tk.Y)
        self.node_listbox.config(yscrollcommand=sb.set)
        self.node_listbox.bind('<<ListboxSelect>>', self.handle_node_selection)
        self.selected_path_label = ttk.Label(sel, text="Selected Path: (None)")
        self.selected_path_label.pack(anchor=tk.W, pady=5)
        self.build_btn = ttk.Button(sel, text="Build Circuit", command=self.build_circuit_thread, state=tk.DISABLED)
        self.build_btn.pack(pady=5)

        # Fetch frame
        fet = ttk.LabelFrame(self.root, text="3. Fetch Message via Local Server", padding=10)
        fet.pack(fill=tk.X, padx=10, pady=5)
        inner = ttk.Frame(fet)
        inner.pack(fill=tk.X)
        ttk.Label(inner, text="Message:").pack(side=tk.LEFT)
        self.msg_var = tk.StringVar(value="hello, world")
        ttk.Entry(inner, textvariable=self.msg_var, width=40).pack(side=tk.LEFT, padx=5)
        self.fetch_btn = ttk.Button(inner, text="Fetch", command=self.fetch_url_thread, state=tk.DISABLED)
        self.fetch_btn.pack(side=tk.LEFT, padx=5)

        # Status log
        self.status = ScrolledText(self.root, height=12, state=tk.DISABLED)
        self.status.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def update_status(self, msg, clear=False):
        self.status.config(state=tk.NORMAL)
        if clear:
            self.status.delete('1.0', tk.END)
        self.status.insert(tk.END, msg + '\n')
        self.status.see(tk.END)
        self.status.config(state=tk.DISABLED)

    def set_ui_state(self, state):
        mapping = {
            'initial':      dict(start='normal', list='disabled', build='disabled', fetch='disabled'),
            'nodes_started':dict(start='disabled', list='normal', build='disabled', fetch='disabled'),
            'building':     dict(start='disabled', list='disabled', build='disabled', fetch='disabled'),
            'circuit_ready':dict(start='disabled', list='disabled', build='disabled', fetch='normal'),
            'fetching':     dict(start='disabled', list='disabled', build='disabled', fetch='disabled'),
        }
        cfg = mapping.get(state)
        if not cfg: return
        self.start_btn.config(state=cfg['start'])
        self.node_listbox.config(state=cfg['list'])
        self.build_btn.config(state=cfg['build'])
        self.fetch_btn.config(state=cfg['fetch'])

    def start_nodes_thread(self):
        try:
            nr, nh = self.relays_var.get(), self.hops_var.get()
            assert nr > 0 and nh > 0 and nh <= nr
        except Exception:
            messagebox.showerror("Input Error", "#relays>0, #hops>0, hops<=relays")
            return
        self.num_hops_required = nh
        self.update_status("Clearing old directory file...", clear=True)
        clear_directory_file()
        self.update_status("Starting nodes...", clear=False)
        self.set_ui_state('building')
        threading.Thread(target=self.start_nodes_task, args=(nr,), daemon=True).start()

    def start_nodes_task(self, num_relays):
        self.all_node_objects.clear()
        for i in range(num_relays):
            port = find_free_port()
            node = Node(f"Relay{i}", host="127.0.0.1", port=port)
            node.start()
            self.all_node_objects.append(node)
        # Wait for the directory to populate
        for _ in range(20):
            if os.path.exists(NODES_DIRECTORY_FILE): break
            time.sleep(0.05)
        with open(NODES_DIRECTORY_FILE) as f:
            infos = json.load(f)
        self.update_queue.put(('state', 'nodes_started'))
        self.update_queue.put(('nodeList', infos))
        self.update_queue.put(('status', f'Started {len(infos)} nodes'))

    def update_node_list(self, infos):
        """Populate the listbox and enable selection."""
        self.relay_nodes_info = infos
        self.selected_hops.clear()
        self.node_listbox.config(state=tk.NORMAL)
        self.node_listbox.delete(0, tk.END)
        for n in infos:
            self.node_listbox.insert(tk.END, n['address'])
        self.prompt_label.config(text=f"Select {self.num_hops_required} relays for circuit")
        self.build_btn.config(state=tk.DISABLED)

    def handle_node_selection(self, event):
        sel = self.node_listbox.curselection()
        if not sel: return
        idx = sel[0]
        if len(self.selected_hops) < self.num_hops_required:
            hop = self.relay_nodes_info[idx]
            self.selected_hops.append(hop)
            self.node_listbox.itemconfig(idx, bg='lightblue')
            path = " -> ".join(h['address'] for h in self.selected_hops)
            self.selected_path_label.config(text=f"Selected Path: {path}")
            if len(self.selected_hops) == self.num_hops_required:
                self.build_btn.config(state=tk.NORMAL)

    def build_circuit_thread(self):
        self.update_status("Building circuit...", clear=False)
        self.set_ui_state('building')
        threading.Thread(target=self.build_circuit_task, daemon=True).start()

    def build_circuit_task(self):
        self.client_node = self.all_node_objects[0]
        circ = self.client_node.auto_build_random_circuit(hops_count=self.num_hops_required, max_retries=5)
        if circ is None:
            self.update_queue.put(('status', 'Circuit build failed'))
            self.update_queue.put(('state','nodes_started'))
        else:
            self.current_circuit_id = circ
            self.update_queue.put(('status', f'Built circuit {circ}'))
            self.update_queue.put(('state','circuit_ready'))

    def fetch_url_thread(self):
        msg = self.msg_var.get().strip()
        if not msg:
            messagebox.showwarning("Input Error", "Enter a message")
            return
        port = find_free_port()
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self2):
                if self2.path == '/message.json':
                    self2.send_response(200)
                    self2.send_header('Content-Type', 'application/json')
                    self2.end_headers()
                    self2.wfile.write(json.dumps({'message': msg}).encode())
                else:
                    self2.send_response(404)
                    self2.end_headers()
        srv = HTTPServer(('127.0.0.1', port), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{port}/message.json"
        self.update_status(f"Fetching local message from {url}")
        self.set_ui_state('fetching')
        def task():
            res = self.client_node.fetch_url(url)
            self.update_queue.put(('status', f'Result: {res}'))
            self.update_queue.put(('state','circuit_ready'))
            srv.shutdown()
        threading.Thread(target=task, daemon=True).start()

    def check_queue(self):
        try:
            while True:
                typ, val = self.update_queue.get_nowait()
                if typ == 'status':
                    self.update_status(val)
                elif typ == 'nodeList':
                    self.update_node_list(val)
                elif typ == 'state':
                    self.set_ui_state(val)
        except queue.Empty:
            pass
        self.root.after(100, self.check_queue)

if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style(root)
    if 'clam' in style.theme_names():
        style.theme_use('clam')
    app = CircuitBuilderApp(root)
    root.mainloop()
