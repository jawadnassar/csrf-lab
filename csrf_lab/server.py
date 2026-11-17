"""The HTTP server: one process, three sites, routed by the Host header."""

from __future__ import annotations

import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import bank, evil, uploads
from .config import CERT_FILE, KEY_FILE, LabConfig, ensure_certificate
from .http_util import Request, parse_cookies, parse_form
from .state import LabState

MAX_BODY = 1 << 20


class Router:
    def __init__(self, config: LabConfig, state: LabState) -> None:
        self.config = config
        self.state = state
        self.by_host = {
            config.hosts["bank"]: ("bank", bank.handle),
            config.hosts["evil"]: ("evil", evil.handle),
            config.hosts["uploads"]: ("uploads", uploads.handle),
        }

    def role_for(self, host_header: str) -> tuple[str, object] | None:
        host = host_header.split(":", 1)[0].lower()
        return self.by_host.get(host)


def make_handler(router: Router):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # keep the terminal readable
            pass

        def _dispatch(self, method: str) -> None:
            from urllib.parse import urlsplit, parse_qs

            host_header = self.headers.get("Host", "")
            match = router.role_for(host_header)
            if not match:
                self._send(404, b"Unknown host. Use one of the lab hostnames.", "text/plain")
                return
            role, handler = match

            split = urlsplit(self.path)
            length = min(int(self.headers.get("Content-Length", 0) or 0), MAX_BODY)
            body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            content_type = self.headers.get("Content-Type", "")

            headers = {k.lower(): v for k, v in self.headers.items()}
            raw = self._raw_request(method, split, body)

            request = Request(
                method=method,
                path=split.path,
                query=parse_qs(split.query, keep_blank_values=True),
                form=parse_form(body, content_type),
                headers=headers,
                cookies=parse_cookies(self.headers.get("Cookie")),
                raw=raw,
                body=body,
                host_role=role,
                config=router.config,
                state=router.state,
            )
            response = handler(request)
            self._emit(response)

        def _raw_request(self, method, split, body: str) -> str:
            path = split.path + (f"?{split.query}" if split.query else "")
            lines = [f"{method} {path} HTTP/1.1"]
            for key, value in self.headers.items():
                lines.append(f"{key}: {value}")
            text = "\n".join(lines) + "\n\n"
            if body:
                text += body if len(body) <= 2048 else body[:2048] + "...(truncated)"
            return text

        def _emit(self, response) -> None:
            has_ct = any(name.lower() == "content-type" for name, _ in response.headers)
            self.send_response(response.status)
            if not has_ct:
                self.send_header("Content-Type", response.content_type)
            self.send_header("Content-Length", str(len(response.body)))
            for name, value in response.headers:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(response.body)

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def do_HEAD(self):
            self._dispatch("HEAD")

    return Handler


def serve(config: LabConfig) -> None:
    ensure_certificate(config)
    state = LabState()
    router = Router(config, state)
    httpd = ThreadingHTTPServer((config.bind, config.port), make_handler(router))

    if config.scheme == "https":
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print_banner(config)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        httpd.shutdown()


def print_banner(config: LabConfig) -> None:
    line = "=" * 68
    print(line)
    print("  CSRF teaching lab")
    print(line)
    print(f"  Bank (victim)   {config.bank_origin}")
    print(f"  Attacker        {config.evil_origin}")
    print(f"  Sibling host    {config.uploads_origin}")
    print(f"  Login           demo / demo")
    print(line)
    if config.needs_hosts_file:
        print("  These .test names need an /etc/hosts entry. If the pages do not load,")
        print("  run ./setup-hosts.sh (it shows the exact line before touching anything).")
    if config.scheme == "https":
        print("  HTTPS uses a self-signed certificate. Your browser will warn once per")
        print("  hostname; accept it to proceed. This is expected for a local lab.")
    for note in config.degradations():
        print(f"  NOTE: {note}")
    print(f"  Open {config.bank_origin}/self-check first to confirm your browser.")
    print(line)
