"""Local OTLP endpoint for collector integration tests; no cloud credentials."""
import gzip
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        if self.headers.get('Content-Encoding') == 'gzip':
            body = gzip.decompress(body)
        payload = json.loads(body)
        if Path('/fixture/unavailable').exists():
            self.send_response(503)
            self.end_headers()
            return
        with Path('/fixture/requests.jsonl').open('ab') as output:
            output.write(body + b'\n')
            output.flush()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{}')

    def log_message(self, *args):
        pass


HTTPServer(('127.0.0.1', 4318), Receiver).serve_forever()
