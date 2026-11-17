"""Rendering the HTTP exchange, which is the evidence the whole lab rests on.

The request shown is reconstructed from what the handler actually received, not from what
the lab intended to send, so a surprising result is still an honest one.
"""

from __future__ import annotations

from html import escape

from .context import RequestContext
from .state import Attempt

DECISIVE = {
    "cookie",
    "origin",
    "referer",
    "sec-fetch-site",
    "sec-fetch-mode",
    "content-type",
    "x-http-method-override",
}

DEVTOOLS_HINT = {
    "cookie": "Network tab, pick the request, Headers, Request Headers. Chrome also shows "
    "withheld cookies under the Cookies sub-tab with a reason.",
    "origin": "Network tab, Request Headers.",
    "referer": "Network tab, Request Headers.",
    "sec-fetch-site": "Network tab, Request Headers. Absent on non-trustworthy origins.",
    "content-type": "Network tab, Request Headers. Decides whether a plain form could have sent it.",
}


def build_raw_request(requestline: str, header_lines: list[tuple[str, str]], body: str) -> str:
    text = requestline + "\n"
    for name, value in header_lines:
        text += f"{name}: {value}\n"
    text += "\n"
    if body:
        text += body
    return text


def _highlight_request(raw: str) -> str:
    out = []
    for index, line in enumerate(raw.rstrip("\n").split("\n")):
        if index == 0:
            out.append(f'<span class="hl">{escape(line)}</span>')
            continue
        name = line.split(":", 1)[0].strip().lower() if ":" in line else ""
        if name in DECISIVE:
            out.append(f'<span class="hl">{escape(line)}</span>')
        else:
            out.append(f'<span class="dim">{escape(line)}</span>')
    return "\n".join(out)


def _render_response(attempt: Attempt) -> str:
    reason = {200: "OK", 403: "Forbidden", 405: "Method Not Allowed", 400: "Bad Request"}.get(
        attempt.status, ""
    )
    lines = [f'<span class="hl">HTTP/1.1 {attempt.status} {reason}</span>']
    for name, value in attempt.response_headers:
        lines.append(f'<span class="dim">{escape(name)}: {escape(value)}</span>')
    return "\n".join(lines)


def explain(ctx: RequestContext, verdict) -> list[tuple[str, str]]:
    """Prose for each decisive part of the request, in the order they appear."""
    notes: list[tuple[str, str]] = []
    config = ctx.config

    if ctx.method_was_overridden:
        notes.append(
            (
                "Request line",
                f"The browser sent {ctx.method}, but the application honoured a method "
                f"override and processed it as {ctx.effective_method}. SameSite made its "
                f"decision about the cookie based on the real {ctx.method}.",
            )
        )
    else:
        notes.append(
            ("Request line", f"A {ctx.method} to {ctx.path}. Safe methods must never change state.")
        )

    if "cookie" in ctx.headers:
        if ctx.session:
            notes.append(
                (
                    "Cookie",
                    "The session cookie arrived, so the bank treated this as the logged-in "
                    f"user. The cookie is set with SameSite={ctx.scenario.cookie_samesite} in "
                    "this scenario, and the browser decided that rule allowed it here.",
                )
            )
        else:
            notes.append(
                (
                    "Cookie",
                    "Cookies arrived but none of them identified a valid session, so the bank "
                    "saw an anonymous request.",
                )
            )
    else:
        notes.append(
            (
                "Cookie (absent)",
                "There is no Cookie header. The browser refused to attach the session cookie "
                f"because it is SameSite={ctx.scenario.cookie_samesite} and this request came "
                "from another site. Nothing on the server was consulted to reach that outcome - "
                "this is the browser enforcing a cookie attribute.",
            )
        )

    if ctx.origin is not None:
        same = ctx.origin == config.bank_origin
        notes.append(
            (
                "Origin",
                f"{ctx.origin} - {'the bank itself' if same else 'not the bank'}. Browsers set "
                "this header themselves and pages cannot forge it, which is what makes it "
                "usable as a signal.",
            )
        )
    else:
        notes.append(
            (
                "Origin (absent)",
                "No Origin header. Browsers omit it on same-origin GETs and in some privacy "
                "contexts, so a check that trusts its absence is a check an attacker can turn "
                "off.",
            )
        )

    if ctx.referer is not None:
        notes.append(
            (
                "Referer",
                f"{ctx.referer} - the page that issued the request. The sending page controls "
                "this via Referrer-Policy, and proxies strip it, so it is a weaker signal than "
                "Origin.",
            )
        )
    else:
        notes.append(
            (
                "Referer (absent)",
                "No Referer. The attacking page can guarantee this with a single meta tag, so "
                "any branch that skips validation when it is missing is effectively optional.",
            )
        )

    if ctx.sec_fetch_site is not None:
        meaning = {
            "same-origin": "the request came from the bank itself",
            "same-site": "the request came from a different origin on the same site, such as a sibling subdomain",
            "cross-site": "the request came from an unrelated site",
            "none": "the user initiated this directly, for example a typed URL or a bookmark",
        }.get(ctx.sec_fetch_site, "an unrecognised value, which servers should ignore")
        notes.append(("Sec-Fetch-Site", f"{ctx.sec_fetch_site} - {meaning}."))
    elif config.fetch_metadata_available:
        notes.append(
            (
                "Sec-Fetch-Site (absent)",
                "Expected on this origin but missing, which is why the fixed implementation "
                "fails closed rather than assuming the request is safe.",
            )
        )
    else:
        notes.append(
            (
                "Sec-Fetch-Site (unavailable)",
                "Browsers only send Fetch Metadata headers to trustworthy origins, and this lab "
                "is currently running on one that does not qualify. Re-run in HTTPS mode to "
                "exercise this layer.",
            )
        )

    if ctx.content_type:
        simple = any(
            kind in ctx.content_type
            for kind in ("application/x-www-form-urlencoded", "multipart/form-data", "text/plain")
        )
        notes.append(
            (
                "Content-Type",
                f"{ctx.content_type} - {'a simple type, so a plain HTML form could send it with no CORS preflight' if simple else 'not a simple type, so a cross-site HTML form could not produce it'}.",
            )
        )

    submitted = ctx.param("csrf")
    if submitted is None:
        notes.append(
            (
                "csrf parameter (absent)",
                "No token was sent at all. Check that your own validation treats this exactly "
                "like a wrong token - a surprising number of implementations do not.",
            )
        )
    else:
        notes.append(("csrf parameter", f"{submitted!r} was submitted."))

    return notes


def exchange_panel(attempt: Attempt, ctx: RequestContext, verdict) -> str:
    notes = explain(ctx, verdict)
    rows = "".join(
        f"<tr><th style='width:230px'>{escape(name)}</th><td>{escape(text)}</td></tr>"
        for name, text in notes
    )
    hints = "".join(
        f"<li><b>{escape(header)}</b>: {escape(hint)}</li>"
        for header, hint in DEVTOOLS_HINT.items()
        if header in ctx.headers or header == "cookie"
    )
    return f"""
<div class="panel">
  <h3>The request the bank received</h3>
  <pre>{_highlight_request(attempt.raw_request)}</pre>
</div>
<div class="panel">
  <h3>The response it sent back</h3>
  <pre>{_render_response(attempt)}</pre>
</div>
<div class="panel">
  <h3>What each part meant</h3>
  <table>{rows}</table>
</div>
<div class="panel tight">
  <h3>Confirm it yourself in DevTools</h3>
  <ul class="note">{hints}</ul>
</div>
"""
