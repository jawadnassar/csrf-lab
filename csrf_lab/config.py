"""Origins, scheme, and the browser capabilities each combination actually gives us.

The lab needs three distinct sites on loopback, and it needs the browser to accept
`SameSite=None; Secure` cookies and to send `Sec-Fetch-*` headers. Those last two are
only available on a "potentially trustworthy" origin, which means HTTPS or a name in the
localhost family. A `.test` name over plain HTTP resolves to loopback but is *not*
trustworthy, so several scenarios cannot be reproduced there. Rather than silently
misteach, the lab records what is available and the UI says when a scenario is degraded.
"""

from __future__ import annotations

import argparse
import dataclasses
import re
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

CERT_DIR = Path(__file__).resolve().parent.parent / "certs"
CERT_FILE = CERT_DIR / "lab.crt"
KEY_FILE = CERT_DIR / "lab.key"

# Two host sets. In both, the uploads host is a subdomain of the bank host, so it is
# cross-origin but same-site with the bank. That is what makes the sibling-domain and
# cookie-injection scenarios possible.
HOST_SETS = {
    "test": {
        "bank": "bank.test",
        "evil": "evil.test",
        "uploads": "uploads.bank.test",
        "app": "app.test",
    },
    "localhost": {
        "bank": "bank.localhost",
        "evil": "evil.localhost",
        "uploads": "uploads.bank.localhost",
        "app": "app.localhost",
    },
}

DEFAULT_PORTS = {"https": 8443, "http": 8080}


@dataclasses.dataclass(frozen=True)
class LabConfig:
    host_set: str
    scheme: str
    port: int
    bind: str = "127.0.0.1"

    @property
    def hosts(self) -> dict[str, str]:
        return HOST_SETS[self.host_set]

    def origin(self, role: str) -> str:
        return f"{self.scheme}://{self.hosts[role]}:{self.port}"

    @property
    def bank_origin(self) -> str:
        return self.origin("bank")

    @property
    def evil_origin(self) -> str:
        return self.origin("evil")

    @property
    def uploads_origin(self) -> str:
        return self.origin("uploads")

    @property
    def bank_host(self) -> str:
        return self.hosts["bank"]

    @property
    def registrable_domain(self) -> str:
        """The bank's site, shared with the uploads host and not with the evil host."""
        return self.hosts["bank"]

    # Capabilities. See the module docstring for why these are not always available.
    @property
    def trustworthy_origin(self) -> bool:
        return self.scheme == "https" or self.host_set == "localhost"

    @property
    def samesite_none_available(self) -> bool:
        return self.trustworthy_origin

    @property
    def fetch_metadata_available(self) -> bool:
        return self.trustworthy_origin

    @property
    def host_prefix_available(self) -> bool:
        # Chrome rejects the __Host- prefix on http://localhost even though it treats the
        # origin as trustworthy for other purposes, so only claim it under real TLS.
        return self.scheme == "https"

    @property
    def needs_hosts_file(self) -> bool:
        return self.host_set == "test"

    def degradations(self) -> list[str]:
        problems = []
        if not self.samesite_none_available:
            problems.append(
                "SameSite=None cookies require Secure, and this origin is not trustworthy, "
                "so the browser will reject them. Scenarios that need a cross-site POST to "
                "carry the session cookie cannot run."
            )
        if not self.fetch_metadata_available:
            problems.append(
                "Sec-Fetch-* headers are only sent to trustworthy origins, so the "
                "Fetch Metadata layer of the fixed implementation is inert here."
            )
        if not self.host_prefix_available:
            problems.append("The __Host- cookie prefix needs HTTPS, so the fixed mode uses a plain cookie name.")
        return problems


def same_origin(url: str, origin: str) -> bool:
    """True only when `url` is on exactly `origin` — same scheme, host, and port.

    Written as a parsed comparison rather than `url.startswith(origin)` because the prefix
    form accepts `https://bank.test:8443@evil.test`: the host is `evil.test` and the bank
    only appears as userinfo. That is the same anchoring mistake one of the scenarios
    teaches against, so the lab should not make it itself.
    """
    target, base = urlsplit(url), urlsplit(origin)
    return target.scheme == base.scheme and target.netloc.lower() == base.netloc.lower()


def _cert_covers(names: set[str]) -> bool:
    """Does the certificate already on disk name every host this run needs?"""
    if not (CERT_FILE.exists() and KEY_FILE.exists()):
        return False
    try:
        out = subprocess.run(
            ["openssl", "x509", "-in", str(CERT_FILE), "-noout", "-ext", "subjectAltName"],
            capture_output=True, text=True, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return False
    return names <= set(re.findall(r"DNS:([^,\s]+)", out))


def ensure_certificate(config: LabConfig) -> None:
    """Generate a self-signed cert covering every lab hostname, if one is not present."""
    if config.scheme != "https":
        return
    names = set(config.hosts.values())
    if _cert_covers(names):
        return
    if CERT_FILE.exists():
        print(
            f"The certificate in {CERT_DIR}/ does not cover "
            f"{', '.join(sorted(names))} — regenerating it for this host set."
        )
    if not shutil.which("openssl"):
        sys.exit(
            "HTTPS mode needs openssl to generate a self-signed certificate, and it was "
            "not found on PATH. Re-run with --scheme=http --hosts=localhost for a "
            "no-certificate setup, and read the capability warnings the lab prints."
        )
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    san = ",".join(f"DNS:{name}" for name in sorted(names)) + ",DNS:localhost,IP:127.0.0.1"
    print(f"Generating a self-signed certificate for {', '.join(names)} ...")
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(KEY_FILE),
            "-out", str(CERT_FILE),
            "-days", "365",
            "-subj", "/CN=CSRF teaching lab",
            "-addext", f"subjectAltName={san}",
        ],
        check=True,
        capture_output=True,
    )
    print(f"Wrote {CERT_FILE.name} and {KEY_FILE.name} to {CERT_DIR}/")


def parse_args(argv: list[str] | None = None) -> LabConfig:
    parser = argparse.ArgumentParser(
        prog="python3 -m csrf_lab",
        description="A local, loopback-only CSRF teaching lab for presenting to a team.",
    )
    parser.add_argument(
        "--hosts",
        choices=sorted(HOST_SETS),
        default="test",
        help=(
            "Which host set to serve. 'test' uses bank.test/evil.test and needs an "
            "/etc/hosts entry (see setup-hosts.sh); it is the default because those names "
            "are unambiguously cross-site. 'localhost' needs no setup but relies on "
            "browser-specific handling of *.localhost, so run /self-check first."
        ),
    )
    parser.add_argument(
        "--scheme",
        choices=["https", "http"],
        default="https",
        help=(
            "HTTPS (default) uses a generated self-signed certificate and is required for "
            "SameSite=None and Sec-Fetch-* to work on .test names. HTTP needs no "
            "certificate but disables those scenarios unless --hosts=localhost."
        ),
    )
    parser.add_argument("--port", type=int, default=None, help="Defaults to 8443 for https, 8080 for http.")
    args = parser.parse_args(argv)

    port = args.port if args.port is not None else DEFAULT_PORTS[args.scheme]
    return LabConfig(host_set=args.hosts, scheme=args.scheme, port=port)
