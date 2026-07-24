#!/usr/bin/env python3
"""detector_api.py — HTTP API для EIP-712 анализатора. Запуск: python3 detector_api.py [port]"""

import json
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from eip712_detector import PermitAnalyzer

analyzer = PermitAnalyzer()


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            payload = json.loads(body)
            result = analyzer.analyze(payload)
            response = {
                "safe": result.safe,
                "score": result.score,
                "findings": [
                    {"risk": f.risk.value, "param": f.param, "message": f.message}
                    for f in result.findings
                ],
            }
            self.send_response(200)
        except Exception as e:
            response = {"error": str(e)}
            self.send_response(400)
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"status":"ok","service":"eip712-detector"}')

    def log_message(self, fmt, *args):
        pass  # тихий режим


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8887
    print(f"Detector API on 0.0.0.0:{port}")
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
