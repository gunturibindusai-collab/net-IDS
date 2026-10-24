#!/usr/bin/env python3
"""
TestMyNIDS - Test Website & Resource Server
Replication of testmynids.org resource server for offline/lab testing.

Features:
- Serves all required test indicators and payloads (UID, Bad Certs, PE/UPX, PDF, etc.)
- Dynamic handling of Basic Auth, Malicious User-Agents, and C2 Beacon POST requests
- Built-in lightweight SSH banner listener on port 2222 or 22 (optional)
- Real-time console and file logging of incoming probe traffic
- Uses Python standard library only (zero external dependencies)
"""

import argparse
import http.server
import os
import socketserver
import sys
import threading
import time
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESOURCES_DIR = os.path.join(BASE_DIR, "resources")


class TestMyNIDSRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Custom request handler that serves test files and logs NIDS test indicators."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=RESOURCES_DIR, **kwargs)

    def log_message(self, format, *args):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        sys.stdout.write(f"[{timestamp}] [HTTP] {self.address_string()} - {format % args}\n")
        sys.stdout.flush()

    def do_HEAD(self):
        self._inspect_request()
        super().do_HEAD()

    def do_GET(self):
        self._inspect_request()
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        # Endpoint 1: /uid/index.html (ET 2100498)
        if path == "/uid" or path == "/uid/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"uid=0(root) gid=0(root) groups=0(root)\n")
            return

        # Fallback for dynamic query-string matching (e.g. /keywords/kyf?partner_id=123)
        if path.startswith("/keywords/kyf"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"// TestMyNIDS Harmless Adware Indicator\n")
            return

        super().do_GET()

    def do_POST(self):
        self._inspect_request()
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b""

        self.log_message(
            "POST Payload (%d bytes): %s",
            len(post_data),
            post_data.decode("utf-8", errors="replace")[:100],
        )

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK - TestMyNIDS Beacon Received\n")

    def _inspect_request(self):
        """Analyze and log security test indicators."""
        auth_header = self.headers.get("Authorization", "")
        if auth_header:
            self.log_message("-> Indicator Observed: Basic Auth Header: %s", auth_header)

        ua = self.headers.get("User-Agent", "")
        if ua:
            suspicious_uas = ["BlackSun", "HttpDownload", "agent", "MSIE", "JEDI-VCL", "Nintendo Wii", "sleep 20"]
            for s in suspicious_uas:
                if s.lower() in ua.lower():
                    self.log_message("-> Indicator Observed: Suspicious User-Agent: %s", ua)
                    break


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def run_ssh_stub(host="0.0.0.0", port=2222):
    """Lightweight SSH banner simulator for port 22 / 2222 testing."""
    import socket

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(5)
        print(f"[*] SSH Test Listener active on {host}:{port}")
        while True:
            conn, addr = sock.accept()
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}] [SSH] Connection from {addr[0]}:{addr[1]}")
            try:
                conn.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
                time.sleep(0.5)
            except Exception:
                pass
            finally:
                conn.close()
    except PermissionError:
        print(f"[!] Warning: Cannot bind SSH stub to port {port} (requires root/admin privileges). Skipping.")
    except Exception as e:
        print(f"[!] SSH stub notice: {e}")


def main():
    parser = argparse.ArgumentParser(description="TestMyNIDS Local Resource Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host interface to bind (default: 0.0.0.0)")
    parser.add_argument("--port", "-p", type=int, default=8080, help="HTTP port to bind (default: 8080)")
    parser.add_argument("--ssh-port", type=int, default=0, help="Optional SSH stub port (e.g. 22 or 2222)")
    args = parser.parse_args()

    print("=================================================================")
    print("             TestMyNIDS Resource Server (Replica)                ")
    print("=================================================================")
    print(f"[*] Serving resources from: {RESOURCES_DIR}")
    print(f"[*] HTTP Server listening on: http://{args.host}:{args.port}")

    if args.ssh_port > 0:
        ssh_thread = threading.Thread(target=run_ssh_stub, args=(args.host, args.ssh_port), daemon=True)
        ssh_thread.start()

    server = ThreadedHTTPServer((args.host, args.port), TestMyNIDSRequestHandler)

    try:
        print("[+] Ready for tmNIDS test runner requests (Press Ctrl+C to stop)...")
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down TestMyNIDS Resource Server.")
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
