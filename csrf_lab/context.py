"""Everything a validator is allowed to look at, assembled from the real request."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .config import LabConfig
    from .scenarios import Scenario
    from .state import LabState, Session

METHOD_OVERRIDE_HEADER = "X-HTTP-Method-Override"
METHOD_OVERRIDE_PARAM = "_method"


@dataclasses.dataclass
class RequestContext:
    method: str
    path: str
    query: dict[str, list[str]]
    form: dict[str, list[str]]
    headers: dict[str, str]
    cookies: dict[str, str]
    raw_request: str
    config: "LabConfig"
    scenario: "Scenario"
    state: "LabState"
    session: "Session | None"

    def param(self, name: str) -> str | None:
        """Form value first, then query string. Returns None when absent entirely.

        The difference between absent and empty matters: one of the scenarios skips
        validation when the parameter is missing but rejects a wrong value.
        """
        if name in self.form:
            return self.form[name][0]
        if name in self.query:
            return self.query[name][0]
        return None

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())

    @property
    def origin(self) -> str | None:
        return self.header("origin")

    @property
    def referer(self) -> str | None:
        return self.header("referer")

    @property
    def sec_fetch_site(self) -> str | None:
        return self.header("sec-fetch-site")

    @property
    def content_type(self) -> str:
        return self.header("content-type") or ""

    @property
    def effective_method(self) -> str:
        """The method after override, when the scenario enables override handling.

        ASP.NET Core ships HttpMethodOverride middleware, so this is not a toy: a
        top-level GET navigation can be turned back into a POST after SameSite=Lax has
        already let the cookie through.
        """
        if not self.scenario.method_override_enabled:
            return self.method
        override = self.header(METHOD_OVERRIDE_HEADER) or self.param(METHOD_OVERRIDE_PARAM)
        if override and override.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
            return override.upper()
        return self.method

    @property
    def method_was_overridden(self) -> bool:
        return self.effective_method != self.method
