#!/usr/bin/env python3
"""Tiny HTTP-only HMI backend for bench testing the ESP display."""

from __future__ import annotations

import argparse
import json
import socketserver
import threading
import time
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


class DemoState:
    def __init__(self, initial: str) -> None:
        self._lock = threading.Lock()
        self._status = initial
        self._sequence = 1
        self.stream_generation = int(time.time() * 1000)
        self.stream_id = f"mock-{uuid.uuid4().hex[:8]}"

    def set_status(self, status: str) -> None:
        with self._lock:
            if self._status != status:
                self._status = status
                self._sequence += 1

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            attack = self._status == "ATTACK"
            return {
                "schema_version": 1,
                "stream_generation": self.stream_generation,
                "stream_id": self.stream_id,
                "seq": self._sequence,
                "status": self._status,
                "valid_for_ms": 10_000,
                "active_alerts": 1 if attack else 0,
                "incident": (
                    {
                        "id": "mock-incident-1",
                        "node_id": "esp-03",
                        "attack_class": "deauth_flood",
                    }
                    if attack
                    else None
                ),
                "sensors": {"online": 3, "expected": 3},
                "metrics": {"attack_frames_detected": 247 if attack else 0},
            }


class Handler(BaseHTTPRequestHandler):
    server: "DemoServer"

    def _send_json(self, status: HTTPStatus, payload: object) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = urlparse(self.path).path
        if path == "/v1/hmi/status":
            self._send_json(HTTPStatus.OK, self.server.demo_state.snapshot())
            return
        if path == "/":
            self._send_json(
                HTTPStatus.OK,
                {
                    "service": "Defense HMI mock backend",
                    "status": self.server.demo_state.snapshot(),
                    "commands": [
                        "POST /demo/safe",
                        "POST /demo/attack",
                        "POST /demo/unknown",
                    ],
                },
            )
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"detail": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = urlparse(self.path).path
        mapping = {
            "/demo/safe": "SAFE",
            "/demo/attack": "ATTACK",
            "/demo/unknown": "UNKNOWN",
        }
        status = mapping.get(path)
        if status is None:
            self._send_json(HTTPStatus.NOT_FOUND, {"detail": "not found"})
            return
        self.server.demo_state.set_status(status)
        self._send_json(HTTPStatus.OK, self.server.demo_state.snapshot())

    def log_message(self, message: str, *args: object) -> None:
        print(f"[mock] {self.address_string()} - {message % args}")


class DemoServer(ThreadingHTTPServer):
    def server_bind(self) -> None:
        # HTTPServer performs a reverse-DNS lookup during startup. Avoid that
        # unnecessary dependency so the bench mock also starts on offline LANs.
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = int(port)

    def __init__(self, address: tuple[str, int], demo_state: DemoState) -> None:
        super().__init__(address, Handler)
        self.demo_state = demo_state


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument(
        "--initial", choices=("SAFE", "ATTACK", "UNKNOWN"), default="SAFE"
    )
    args = parser.parse_args()

    server = DemoServer((args.host, args.port), DemoState(args.initial))
    print(f"Defense HMI mock listening on http://{args.host}:{args.port}")
    print("Switch state with POST /demo/safe, /demo/attack or /demo/unknown")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
