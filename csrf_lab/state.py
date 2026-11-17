"""In-memory lab state: the victim's account, sessions, and the log of attempts.

Nothing is persisted. Restarting the process resets the lab.
"""

from __future__ import annotations

import dataclasses
import secrets
import threading
import time

STARTING_EMAIL = "demo@bank.test"
DEMO_USER = "demo"
DEMO_PASSWORD = "demo"


@dataclasses.dataclass
class Session:
    sid: str
    username: str
    csrf_token: str
    created_at: float = dataclasses.field(default_factory=time.time)
    # Set at login for the scenario that ties the CSRF token to a non-session cookie.
    csrf_key: str = ""


@dataclasses.dataclass
class Verdict:
    """The outcome of one attempt, and crucially which layer produced it."""

    allowed: bool
    layer: str
    reason: str

    @staticmethod
    def allow(reason: str) -> "Verdict":
        return Verdict(allowed=True, layer=Layer.NOTHING, reason=reason)

    @staticmethod
    def block(layer: str, reason: str) -> "Verdict":
        return Verdict(allowed=False, layer=layer, reason=reason)


class Layer:
    """Which defense stopped a request. The whole point of the lab is telling these apart."""

    NOTHING = "nothing"
    BROWSER_COOKIE = "the browser (SameSite)"
    METHOD = "the method check"
    TOKEN = "the CSRF token check"
    ORIGIN = "the Origin/Referer check"
    FETCH_METADATA = "the Sec-Fetch-Site check"


@dataclasses.dataclass
class Attempt:
    number: int
    scenario_id: str
    scenario_title: str
    raw_request: str
    status: int
    response_headers: list[tuple[str, str]]
    verdict: Verdict
    email_before: str
    email_after: str
    validator_name: str
    at: float = dataclasses.field(default_factory=time.time)

    @property
    def changed_state(self) -> bool:
        return self.email_before != self.email_after


class LabState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.email = STARTING_EMAIL
        self.sessions: dict[str, Session] = {}
        # A pool of every token the server has ever issued, with no record of which session
        # it belongs to. This is what makes the "token not tied to the session" flaw real.
        self.issued_tokens: set[str] = set()
        self.attempts: list[Attempt] = []
        self.current_scenario_id = ""
        # Per-scenario presenter overrides, e.g. flipping SameSite during the
        # blocked-for-the-wrong-reason scenario.
        self.samesite_override: str | None = None
        # Results of the /self-check probes, keyed by probe kind. Populated by real
        # requests the browser makes, so it reports what this browser actually does rather
        # than what the lab assumes.
        self.probe_results: dict[str, dict] = {}

    def record_probe(self, kind: str, result: dict) -> None:
        with self._lock:
            self.probe_results[kind] = result

    def new_session(self, username: str = DEMO_USER) -> Session:
        with self._lock:
            session = Session(
                sid=secrets.token_urlsafe(24),
                username=username,
                csrf_token=secrets.token_urlsafe(24),
                csrf_key=secrets.token_urlsafe(12),
            )
            self.sessions[session.sid] = session
            self.issued_tokens.add(session.csrf_token)
            return session

    def mint_pool_token(self) -> str:
        """A token the attacker obtained by logging into their own account."""
        with self._lock:
            token = secrets.token_urlsafe(24)
            self.issued_tokens.add(token)
            return token

    def session_for(self, sid: str | None) -> Session | None:
        if not sid:
            return None
        return self.sessions.get(sid)

    def set_email(self, value: str) -> None:
        with self._lock:
            self.email = value

    def reset_account(self) -> None:
        with self._lock:
            self.email = STARTING_EMAIL

    def record(self, attempt_fields: dict) -> Attempt:
        with self._lock:
            attempt = Attempt(number=len(self.attempts) + 1, **attempt_fields)
            self.attempts.append(attempt)
            return attempt

    def clear_log(self) -> None:
        with self._lock:
            self.attempts.clear()
