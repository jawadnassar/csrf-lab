"""The server-side CSRF checks, one function per scenario.

Each function is displayed verbatim in the UI via inspect.getsource, so what the room
reads is exactly what ran. Every validator except `fully_validated` is deliberately
flawed, and the flaws are the ones catalogued by PortSwigger's Web Security Academy:
https://portswigger.net/web-security/csrf/bypassing-token-validation
https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses
"""

from __future__ import annotations

import dataclasses
import hmac
import inspect
from typing import Callable

from .context import RequestContext
from .state import Layer, Verdict

SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


# --------------------------------------------------------------------------------------
# Flawed implementations
# --------------------------------------------------------------------------------------


def no_validation(ctx: RequestContext) -> Verdict:
    """No CSRF defense at all. Possessing the session cookie is treated as intent."""
    return Verdict.allow("There is no CSRF check. The session cookie alone authorized this change.")


def token_checked_on_post_only(ctx: RequestContext) -> Verdict:
    """A token, enforced on POST and skipped on every other method."""
    if ctx.effective_method != "POST":
        return Verdict.allow(
            f"The token is only validated on POST, and this was a {ctx.effective_method}, "
            "so validation was skipped entirely."
        )
    if ctx.session and hmac.compare_digest(ctx.param("csrf") or "", ctx.session.csrf_token):
        return Verdict.allow("Token matched the session token.")
    return Verdict.block(Layer.TOKEN, "Token missing or wrong on a POST.")


def token_checked_when_present(ctx: RequestContext) -> Verdict:
    """A token, validated when it arrives and skipped when the parameter is absent.

    A wrong token is rejected, which is what makes this so convincing in review: the
    obvious negative test passes. Omitting the parameter entirely walks straight through.
    """
    submitted = ctx.param("csrf")
    if submitted is None:
        return Verdict.allow("No csrf parameter was present, so the check was skipped.")
    if ctx.session and hmac.compare_digest(submitted, ctx.session.csrf_token):
        return Verdict.allow("Token matched the session token.")
    return Verdict.block(Layer.TOKEN, "A csrf parameter was present but did not match.")


def token_from_global_pool(ctx: RequestContext) -> Verdict:
    """The token must be one the server issued, but it is never tied to this session.

    An attacker logs into their own account, keeps their own valid token, and sends it
    along with the victim's cookie.
    """
    submitted = ctx.param("csrf")
    if submitted and submitted in ctx.state.issued_tokens:
        return Verdict.allow(
            "The token is one the server issued, so it was accepted. It was never checked "
            "against the session making the request."
        )
    return Verdict.block(Layer.TOKEN, "Token is not in the pool of issued tokens.")


def token_tied_to_non_session_cookie(ctx: RequestContext) -> Verdict:
    """The token is bound to a `csrfKey` cookie rather than to the session.

    Typical when session handling and CSRF protection come from two different components.
    Any host that can write a cookie on the parent domain controls both halves.
    """
    key = ctx.cookies.get("csrfKey", "")
    submitted = ctx.param("csrf") or ""
    if key and hmac.compare_digest(submitted, f"token-for-{key}"):
        return Verdict.allow("Token matches the csrfKey cookie, which is not the session cookie.")
    return Verdict.block(Layer.TOKEN, "Token does not correspond to the csrfKey cookie.")


def naive_double_submit(ctx: RequestContext) -> Verdict:
    """The token parameter is compared only against a cookie of the same name.

    The server keeps no record of its own, so anything that can set the cookie can forge a
    matching pair. OWASP marks this pattern DISCOURAGED for exactly this reason.
    """
    submitted = ctx.param("csrf") or ""
    cookie = ctx.cookies.get("csrf", "")
    if submitted and cookie and hmac.compare_digest(submitted, cookie):
        return Verdict.allow("The parameter matched the cookie. The server held no copy to compare against.")
    return Verdict.block(Layer.TOKEN, "The csrf parameter did not match the csrf cookie.")


def referer_checked_when_present(ctx: RequestContext) -> Verdict:
    """A Referer check that is skipped whenever the header is absent."""
    referer = ctx.referer
    if referer is None:
        return Verdict.allow("No Referer header arrived, so the check was skipped.")
    if referer.startswith(ctx.config.bank_origin):
        return Verdict.allow("Referer begins with the bank's origin.")
    return Verdict.block(Layer.ORIGIN, "Referer did not begin with the bank's origin.")


def referer_matched_loosely(ctx: RequestContext) -> Verdict:
    """A Referer check that looks for the hostname anywhere in the URL."""
    referer = ctx.referer
    if referer is None:
        return Verdict.block(Layer.ORIGIN, "No Referer header to check.")
    if ctx.config.bank_host in referer:
        return Verdict.allow(
            f"The Referer contains {ctx.config.bank_host!r} somewhere in the URL, which was "
            "enough to pass."
        )
    return Verdict.block(Layer.ORIGIN, "The bank's hostname does not appear in the Referer.")


# --------------------------------------------------------------------------------------
# The fixed implementation
# --------------------------------------------------------------------------------------


def fully_validated(ctx: RequestContext) -> Verdict:
    """Synchronizer token bound to the session, plus Origin and Fetch Metadata checks.

    Validation runs on every state-changing request regardless of method or content type,
    and a missing token is rejected exactly like a wrong one.
    """
    if ctx.method in SAFE_METHODS:
        return Verdict.block(
            Layer.METHOD,
            f"{ctx.method} cannot change state. The endpoint only accepts POST, so a method "
            "override cannot resurrect a GET either.",
        )

    site = ctx.sec_fetch_site
    if site is not None:
        if site == "cross-site":
            return Verdict.block(Layer.FETCH_METADATA, "Sec-Fetch-Site said cross-site on a state-changing request.")
    elif ctx.config.fetch_metadata_available:
        return Verdict.block(Layer.FETCH_METADATA, "Sec-Fetch-Site was absent where it was expected, so this failed closed.")

    expected = ctx.config.bank_origin
    if ctx.origin is not None:
        if ctx.origin != expected:
            return Verdict.block(Layer.ORIGIN, f"Origin was {ctx.origin!r}, not {expected!r}.")
    elif ctx.referer is None or not (ctx.referer == expected or ctx.referer.startswith(expected + "/")):
        return Verdict.block(
            Layer.ORIGIN,
            "No Origin header, and the Referer did not match the bank's full origin. The "
            "comparison is anchored, so bank.test.evil.test does not pass.",
        )

    submitted = ctx.param("csrf") or ""
    if not ctx.session:
        return Verdict.block(Layer.TOKEN, "No session, so there is no token to compare against.")
    if not hmac.compare_digest(submitted, ctx.session.csrf_token):
        return Verdict.block(
            Layer.TOKEN,
            "The token was missing or did not match this session's token. Absent and wrong "
            "are treated identically.",
        )
    return Verdict.allow("Token matched this session, Origin matched, and the method was POST.")


# --------------------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Validator:
    name: str
    label: str
    func: Callable[[RequestContext], Verdict]
    # Substrings of the source that the UI highlights as the flaw.
    flaws: tuple[str, ...] = ()

    @property
    def source(self) -> str:
        return inspect.getsource(self.func)

    @property
    def summary(self) -> str:
        return inspect.getdoc(self.func) or ""

    def __call__(self, ctx: RequestContext) -> Verdict:
        return self.func(ctx)


VALIDATORS: dict[str, Validator] = {
    v.name: v
    for v in [
        Validator("no_validation", "No CSRF defense", no_validation),
        Validator(
            "token_checked_on_post_only",
            "Token enforced on POST only",
            token_checked_on_post_only,
            flaws=('if ctx.effective_method != "POST":',),
        ),
        Validator(
            "token_checked_when_present",
            "Token validated only when the parameter exists",
            token_checked_when_present,
            flaws=("if submitted is None:",),
        ),
        Validator(
            "token_from_global_pool",
            "Token checked against a global pool",
            token_from_global_pool,
            flaws=("in ctx.state.issued_tokens",),
        ),
        Validator(
            "token_tied_to_non_session_cookie",
            "Token bound to a non-session cookie",
            token_tied_to_non_session_cookie,
            flaws=('ctx.cookies.get("csrfKey", "")',),
        ),
        Validator(
            "naive_double_submit",
            "Naive double-submit cookie",
            naive_double_submit,
            flaws=('cookie = ctx.cookies.get("csrf", "")',),
        ),
        Validator(
            "referer_checked_when_present",
            "Referer checked only when present",
            referer_checked_when_present,
            flaws=("if referer is None:",),
        ),
        Validator(
            "referer_matched_loosely",
            "Referer matched by substring",
            referer_matched_loosely,
            flaws=("if ctx.config.bank_host in referer:",),
        ),
        Validator("fully_validated", "Fixed: session-bound token, Origin, Fetch Metadata", fully_validated),
    ]
}
