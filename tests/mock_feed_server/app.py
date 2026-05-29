from __future__ import annotations

import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any, ClassVar


class RouteHandler(BaseHTTPRequestHandler):
    routes: ClassVar[dict[str, dict[str, Any]]] = {}

    def log_message(self, fmt: str, *args: Any) -> None:  # pragma: no cover
        return

    def do_GET(self) -> None:
        route = self.routes.get(self.path)
        if not route:
            self.send_response(404)
            self.end_headers()
            return
        delay = float(route.get("delay", 0))
        if delay:
            time.sleep(delay)
        status = int(route.get("status", 200))
        body = route.get("body", "")
        if isinstance(body, str):
            payload = body.encode("utf-8")
        else:
            payload = bytes(body)
        content_type = route.get("content_type", "application/octet-stream")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def build_server(
    routes: dict[str, dict[str, Any]], host: str = "127.0.0.1", port: int = 0
) -> ThreadingHTTPServer:
    RouteHandler.routes = routes
    return ThreadingHTTPServer((host, port), RouteHandler)


def serve_in_thread(routes: dict[str, dict[str, Any]], host: str = "127.0.0.1", port: int = 0):
    server = build_server(routes, host=host, port=port)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--config", default="")
    args = parser.parse_args()
    routes: ClassVar[dict[str, dict[str, Any]]] = {}
    if args.config:
        routes = json.loads(Path(args.config).read_text(encoding="utf-8"))
    server = build_server(routes, args.host, args.port)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
