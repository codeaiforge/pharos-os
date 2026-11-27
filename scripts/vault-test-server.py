#!/usr/bin/env python3
"""The host side of the `vault` test kernel (#284, gateway.md): an HTTPS
server on Python's standard library only, started by `cargo xtask`.

  GET  /items  200 `items ok` if `Authorization` is `Bearer <secret>`, else 401
  GET  /echo   200 `you sent: <Authorization>`: the gateway must strip it
  POST /items  201 `created <body length>` with the same check; the log
               names the body by the first 16 hex digits of its SHA-256
               (#328): test bodies only, never a header

The secret is read from the secrets file the machine gets (the value of
`test-token`). The log names each request and whether its header was the
expected one, never the header or the secret.

Usage: vault-test-server.py PORT CERT KEY SECRETS LOG
"""

import hashlib
import http.server
import ssl
import sys


def main():
    port, cert, key, secrets, log_path = sys.argv[1:6]
    with open(secrets, encoding="ascii") as f:
        values = dict(line.rstrip("\n").split(" ", 1) for line in f if line.strip())
    expected = "Bearer " + values["test-token"]
    log = open(log_path, "a", buffering=1, encoding="ascii")

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def answer(self, code, body):
            data = body.encode("ascii")
            self.send_response(code)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
            self.close_connection = True

        def authorized(self):
            ok = self.headers.get("Authorization") == expected
            log.write(f"{self.command} {self.path} auth={'ok' if ok else 'wrong'}\n")
            return ok

        def do_GET(self):
            if self.path == "/items":
                if self.authorized():
                    self.answer(200, "items ok")
                else:
                    self.answer(401, "unauthorized")
            elif self.path == "/echo":
                self.authorized()
                self.answer(200, "you sent: " + self.headers.get("Authorization", ""))
            else:
                log.write(f"{self.command} {self.path} unknown\n")
                self.answer(404, "not found")

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            log.write(f"POST {self.path} body {hashlib.sha256(body).hexdigest()[:16]}\n")
            if self.path == "/items" and self.authorized():
                self.answer(201, f"created {len(body)}")
            else:
                self.answer(401, "unauthorized")

        def log_message(self, *args):
            pass

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert, key)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", int(port)), Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    log.write("ready\n")
    server.serve_forever()


if __name__ == "__main__":
    main()
