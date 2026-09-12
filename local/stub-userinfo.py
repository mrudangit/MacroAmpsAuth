#!/usr/bin/env python3
"""A stand-in UserInfo endpoint for local testing of amps-auth-service (no identity provider needed).

    python3 local/stub-userinfo.py            # listens on http://127.0.0.1:9999/userinfo

Any bearer token except "bad" is accepted and answered with a fixed user U000001 in group amps-users,
so with the local profile:  curl -i -H 'X-AMPS-Password: anything' http://localhost:8080/amps/v1/permissions/U000001
"""
import json
import socketserver
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USER = {"sub": "U000001", "csmail": "u000001@example.com", "csgroups": ["everyone", "amps-users"]}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth == "Bearer bad":
            self.send_response(401)
            self.end_headers()
            return
        body = json.dumps(USER).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("stub-userinfo:", fmt % args, flush=True)


class Server(ThreadingHTTPServer):
    def server_bind(self):
        # HTTPServer.server_bind does a reverse DNS lookup of the bind address (socket.getfqdn), which
        # can stall for seconds on some networks before the server starts listening. Skip it.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[0], self.server_address[1]


if __name__ == "__main__":
    with Server(("127.0.0.1", 9999), Handler) as server:
        print("stub UserInfo endpoint on http://127.0.0.1:9999/userinfo (Ctrl-C to stop)", flush=True)
        server.serve_forever()
