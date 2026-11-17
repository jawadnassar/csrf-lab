"""Small request/response helpers so the site modules stay readable."""

from __future__ import annotations

import dataclasses
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlparse

from .config import LabConfig
from .state import LabState


@dataclasses.dataclass
class Request:
    method: str
    path: str
    query: dict[str, list[str]]
    form: dict[str, list[str]]
    headers: dict[str, str]
    cookies: dict[str, str]
    raw: str
    body: str
    host_role: str
    config: LabConfig
    state: LabState

    def q(self, name: str, default: str = "") -> str:
        values = self.query.get(name)
        return values[0] if values else default

    def f(self, name: str, default: str = "") -> str:
        values = self.form.get(name)
        return values[0] if values else default


@dataclasses.dataclass
class Response:
    status: int = 200
    body: bytes = b""
    headers: list[tuple[str, str]] = dataclasses.field(default_factory=list)
    content_type: str = "text/html; charset=utf-8"

    def with_header(self, name: str, value: str) -> "Response":
        self.headers.append((name, value))
        return self


def html(body: bytes, status: int = 200) -> Response:
    return Response(status=status, body=body)


def redirect(location: str, extra_headers: list[tuple[str, str]] | None = None) -> Response:
    response = Response(status=302, body=b"")
    response.headers.append(("Location", location))
    for name, value in extra_headers or []:
        response.headers.append((name, value))
    return response


def text(body: str, status: int = 200) -> Response:
    return Response(status=status, body=body.encode(), content_type="text/plain; charset=utf-8")


def not_found() -> Response:
    return Response(status=404, body=b"<h1>404</h1>")


def parse_cookies(header: str | None) -> dict[str, str]:
    if not header:
        return {}
    jar = SimpleCookie()
    try:
        jar.load(header)
    except Exception:  # pragma: no cover - malformed cookies are not the lesson
        return {}
    return {key: morsel.value for key, morsel in jar.items()}


def parse_form(body: str, content_type: str) -> dict[str, list[str]]:
    """Parse the body when it is something an HTML form could have produced.

    text/plain is included on purpose: browsers allow it without a CORS preflight, so an
    API that accepts it is reachable by a cross-site form.
    """
    if "application/x-www-form-urlencoded" in content_type:
        return parse_qs(body, keep_blank_values=True)
    if "text/plain" in content_type:
        return parse_qs(body.replace("\n", "&"), keep_blank_values=True)
    if "application/json" in content_type:
        import json

        try:
            data = json.loads(body or "{}")
        except ValueError:
            return {}
        return {key: [str(value)] for key, value in data.items()} if isinstance(data, dict) else {}
    if "multipart/form-data" in content_type:
        return _parse_multipart(body, content_type)
    return {}


def _parse_multipart(body: str, content_type: str) -> dict[str, list[str]]:
    marker = "boundary="
    if marker not in content_type:
        return {}
    boundary = content_type.split(marker, 1)[1].strip().strip('"')
    fields: dict[str, list[str]] = {}
    for part in body.split("--" + boundary):
        if "name=" not in part:
            continue
        header_block, _, value = part.partition("\r\n\r\n")
        if not _:
            header_block, _, value = part.partition("\n\n")
        name = header_block.split('name="', 1)[-1].split('"', 1)[0]
        fields.setdefault(name, []).append(value.strip().rstrip("-").strip())
    return fields


def same_origin_path(url: str, expected_origin: str) -> str | None:
    """Allowlist check for the redirect gadget: only paths on the bank are reachable.

    The gadget exists to teach that a client-side redirect launders a cross-site request
    into a same-site one. It is not a general-purpose open redirect, so anything outside
    the bank's origin is refused.
    """
    if not url.startswith(expected_origin):
        return None
    parsed = urlparse(url)
    return parsed.path + (f"?{parsed.query}" if parsed.query else "")
