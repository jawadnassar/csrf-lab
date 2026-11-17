"""The victim application, and the presenter UI that wraps it."""

from __future__ import annotations

from html import escape

from . import scenarios as scen
from .context import RequestContext
from .http_util import Request, Response, html, not_found, redirect
from .state import DEMO_PASSWORD, DEMO_USER, Layer, Verdict
from .ui import (
    capability_pills,
    page,
    site_bar,
    validator_panel,
    verdict_banner,
)
from .validators import SAFE_METHODS, VALIDATORS
from .wire import exchange_panel

SESSION_COOKIE = "session"
HOST_PREFIXED_COOKIE = "__Host-session"


# --------------------------------------------------------------------------------------
# Cookies
# --------------------------------------------------------------------------------------


def effective_samesite(req: Request, scenario: scen.Scenario) -> str:
    override = req.state.samesite_override if scenario.offers_samesite_toggle else None
    samesite = override or scenario.cookie_samesite
    if samesite == "None" and not req.config.samesite_none_available:
        # A None cookie must also be Secure, and a Secure cookie is rejected outright on a
        # non-trustworthy origin. Falling back keeps the lab usable; the scenario page says
        # loudly that the intended attack cannot be reproduced here.
        return "Lax"
    return samesite


def session_cookie_name(req: Request, scenario: scen.Scenario) -> str:
    if scenario.fixed and req.config.host_prefix_available:
        return HOST_PREFIXED_COOKIE
    return SESSION_COOKIE


def _cookie(name: str, value: str, samesite: str, config, http_only: bool = True) -> str:
    parts = [f"{name}={value}", "Path=/"]
    if http_only:
        parts.append("HttpOnly")
    # SameSite is always stated explicitly. Chrome's "Lax+POST" exception applies only to
    # cookies that arrive with no SameSite attribute, and it would let a freshly created
    # cookie ride along on a cross-site POST for two minutes - long enough to make the Lax
    # scenarios appear broken in the middle of a presentation.
    parts.append(f"SameSite={samesite}")
    if samesite == "None" or config.trustworthy_origin:
        parts.append("Secure")
    return "; ".join(parts)


def login_cookies(req: Request, scenario: scen.Scenario, session) -> list[tuple[str, str]]:
    samesite = effective_samesite(req, scenario)
    config = req.config
    out = [
        ("Set-Cookie", _cookie(session_cookie_name(req, scenario), session.sid, samesite, config)),
    ]
    # Clear whichever session cookie name we are not using, so switching to and from the
    # fixed scenario does not leave two sessions in the jar.
    stale = SESSION_COOKIE if session_cookie_name(req, scenario) == HOST_PREFIXED_COOKIE else HOST_PREFIXED_COOKIE
    out.append(("Set-Cookie", f"{stale}=; Path=/; Max-Age=0"))
    if scenario.sets_csrf_cookie:
        out.append(("Set-Cookie", _cookie("csrf", session.csrf_token, samesite, config, http_only=False)))
    else:
        out.append(("Set-Cookie", "csrf=; Path=/; Max-Age=0"))
    if scenario.sets_csrf_key_cookie:
        out.append(("Set-Cookie", _cookie("csrfKey", session.csrf_key, samesite, config, http_only=False)))
    else:
        out.append(("Set-Cookie", "csrfKey=; Path=/; Max-Age=0"))
    return out


def current_scenario(req: Request) -> scen.Scenario:
    return scen.BY_ID.get(req.state.current_scenario_id or scen.DEFAULT_SCENARIO_ID, scen.SCENARIOS[0])


def find_session(req: Request):
    for name in (HOST_PREFIXED_COOKIE, SESSION_COOKIE):
        session = req.state.session_for(req.cookies.get(name))
        if session:
            return session
    return None


# --------------------------------------------------------------------------------------
# Routing
# --------------------------------------------------------------------------------------


def handle(req: Request) -> Response:
    path = req.path
    if path == "/":
        return index(req)
    if path == "/login" and req.method == "POST":
        return login(req)
    if path == "/logout":
        return logout(req)
    if path.startswith("/scenario/"):
        return scenario_screen(req, path.split("/scenario/", 1)[1])
    if path == "/email":
        return change_email(req)
    if path == "/log":
        return log_page(req)
    if path == "/reset":
        return reset(req)
    if path.startswith("/samesite/"):
        return set_samesite(req, path.split("/samesite/", 1)[1])
    if path.startswith("/code/"):
        return code_page(req, path.split("/code/", 1)[1])
    if path == "/demo/attacker-token":
        return attacker_token(req)
    if path == "/self-check":
        return self_check(req)
    if path == "/self-check/hit":
        return self_check_hit(req)
    if path == "/self-check/probe-frame":
        return probe_frame(req)
    return not_found()


def _bar(req: Request) -> str:
    scenario = current_scenario(req)
    session = find_session(req)
    who = f"logged in as {session.username}" if session else "not logged in"
    extra = (
        f'<span class="note">{escape(who)} &middot; email <code>{escape(req.state.email)}</code>'
        f' &middot; scenario <b>{escape(scenario.title)}</b></span>'
        f'<a class="btn" href="/">Bank home</a>'
        f'<a class="btn" href="/log">Log</a>'
    )
    return site_bar(req.config, "bank", extra)


def index(req: Request) -> Response:
    scenario = current_scenario(req)
    session = find_session(req)
    if not session:
        body = f"""
<h1>Demo Bank</h1>
<p class="sub">A deliberately vulnerable application that exists only to be attacked from
the site next door.</p>
<div class="panel">
  <form method="post" action="/login">
    <label>Username</label><input type="text" name="username" value="{DEMO_USER}">
    <label>Password</label><input type="text" name="password" value="{DEMO_PASSWORD}">
    <p><button class="btn primary" type="submit">Log in</button></p>
  </form>
</div>
<p class="note">Logging in issues the session cookie configured by the current scenario
({escape(scenario.title)}, SameSite={escape(effective_samesite(req, scenario))}).</p>
"""
        return html(page("Demo Bank - log in", body, site_bar=_bar(req)))

    token_field = (
        f'<input type="hidden" name="csrf" value="{escape(session.csrf_token)}">'
        if scenario.renders_token_field
        else ""
    )
    token_note = (
        "<p class=\"note\">This form carries a CSRF token in a hidden field, placed before "
        "the visible inputs as PortSwigger recommends.</p>"
        if scenario.renders_token_field
        else '<p class="note">This form carries no CSRF token in this scenario.</p>'
    )
    body = f"""
<h1>Your account</h1>
<p class="sub">The legitimate form. It must keep working after the fix, or the fix gets
reverted.</p>
<div class="panel">
  <dl class="kv">
    <dt>Account email</dt><dd>{escape(req.state.email)}</dd>
    <dt>Session cookie</dt><dd>{escape(session_cookie_name(req, scenario))} (SameSite={escape(effective_samesite(req, scenario))})</dd>
    <dt>Session CSRF token</dt><dd>{escape(session.csrf_token[:12])}...</dd>
  </dl>
</div>
<div class="panel">
  <h3>Change your email address</h3>
  <form method="post" action="/email">
    {token_field}
    <label>New email</label><input type="text" name="email" value="{escape(req.state.email)}">
    <p><button class="btn primary" type="submit">Save</button></p>
  </form>
  {token_note}
</div>
{scenario_index(req)}
"""
    return html(page("Demo Bank - account", body, site_bar=_bar(req)))


def scenario_index(req: Request) -> str:
    current = current_scenario(req)
    blocks = []
    track = None
    for scenario in scen.SCENARIOS:
        if scenario.track != track:
            track = scenario.track
            blocks.append(f'<div class="track">{escape(track)}</div>')
        mark = ' class="current"' if scenario.id == current.id else ""
        blocks.append(
            f'<a href="/scenario/{scenario.id}"{mark}>{escape(scenario.title)}'
            f' <span class="note">- {escape(scenario.subtitle)}</span></a>'
        )
    return (
        '<div class="panel scenario-list"><h3>Scenarios</h3>'
        + "".join(blocks)
        + f'<p style="margin-top:16px"><a class="btn" href="/self-check">Run the self-check first</a>'
        f'<a class="btn" href="{escape(req.config.evil_origin)}">Go to the attacker site</a></p></div>'
    )


def login(req: Request) -> Response:
    if req.f("username") != DEMO_USER or req.f("password") != DEMO_PASSWORD:
        return html(page("Login failed", "<h1>Login failed</h1><p><a href='/'>Try again</a></p>"), status=403)
    scenario = current_scenario(req)
    session = req.state.new_session()
    return redirect("/", login_cookies(req, scenario, session))


def logout(req: Request) -> Response:
    return redirect(
        "/",
        [
            ("Set-Cookie", f"{SESSION_COOKIE}=; Path=/; Max-Age=0"),
            ("Set-Cookie", f"{HOST_PREFIXED_COOKIE}=; Path=/; Max-Age=0"),
        ],
    )


def reset(req: Request) -> Response:
    req.state.reset_account()
    return redirect(req.headers.get("referer", "/"))


def set_samesite(req: Request, value: str) -> Response:
    """Presenter toggle used by the blocked-for-the-wrong-reason scenario."""
    if value not in {"None", "Lax", "Strict", "clear"}:
        return not_found()
    req.state.samesite_override = None if value == "clear" else value
    scenario = current_scenario(req)
    session = find_session(req)
    headers = login_cookies(req, scenario, session) if session else []
    return redirect(f"/scenario/{scenario.id}", headers)


def scenario_screen(req: Request, scenario_id: str) -> Response:
    scenario = scen.BY_ID.get(scenario_id)
    if not scenario:
        return not_found()
    switching = req.state.current_scenario_id != scenario_id
    req.state.current_scenario_id = scenario_id
    if switching:
        req.state.samesite_override = None
    session = find_session(req)

    # Re-issue the session cookie so its attributes match this scenario. Without this the
    # room would be looking at a cookie left over from the previous screen.
    headers: list[tuple[str, str]] = []
    if session:
        headers = login_cookies(req, scenario, session)

    validator = VALIDATORS[scenario.validator]
    previous, following = scen.neighbours(scenario.id)
    samesite = effective_samesite(req, scenario)

    unavailable = ""
    if scenario.requires_samesite_none and not req.config.samesite_none_available:
        unavailable = f"""
<div class="bad-box"><b>This scenario cannot be reproduced on the current origin.</b>
It needs the session cookie to ride along on a cross-site POST, which requires
SameSite=None, which requires Secure, which requires a trustworthy origin. The cookie has
been issued as SameSite=Lax instead, so the attack below will be blocked by the browser and
you will not see the flaw. Restart the lab with <code>--scheme=https</code> (or
<code>--hosts=localhost</code>) and re-run the self-check.</div>"""

    toggle = ""
    if scenario.offers_samesite_toggle:
        current_value = req.state.samesite_override or scenario.cookie_samesite
        buttons = "".join(
            f'<a class="btn{" primary" if value == current_value else ""}" '
            f'href="/samesite/{value}">SameSite={value}</a>'
            for value in ("Lax", "None")
        )
        toggle = f"""
<div class="warn-box"><b>Presenter toggle.</b> The application code does not change when you
use this. Only the cookie attribute does.<p style="margin:10px 0 0">{buttons}
<span class="note">currently SameSite={escape(current_value)}</span></p></div>"""

    attacks = attack_links(req, scenario)
    session_note = (
        ""
        if session
        else '<div class="warn-box">You are not logged in, so every attack will fail for an '
        'uninteresting reason. <a href="/">Log in first</a>.</div>'
    )

    body = f"""
<p class="note">{escape(scenario.track)}</p>
<h1>{escape(scenario.title)}</h1>
<p class="sub">{escape(scenario.subtitle)}</p>
{unavailable}
{session_note}
<div class="panel">
  <h3>What this scenario is</h3>
  <p>{escape(scenario.explanation)}</p>
</div>
{toggle}
<div class="grid">
  <div class="panel">
    <h3>How the bank is configured right now</h3>
    <dl class="kv">
      <dt>Session cookie</dt><dd>SameSite={escape(samesite)}{", Secure" if req.config.trustworthy_origin or samesite == "None" else ""}, HttpOnly</dd>
      <dt>CSRF check</dt><dd>{escape(validator.label)}</dd>
      <dt>State-changing GET</dt><dd>{"exists" if scenario.allow_get_mutation else "returns 405"}</dd>
      <dt>Method override</dt><dd>{"honoured" if scenario.method_override_enabled else "ignored"}</dd>
      <dt>Token in the real form</dt><dd>{"yes" if scenario.renders_token_field else "no"}</dd>
    </dl>
  </div>
  <div class="panel">
    <h3>What to watch</h3>
    <p>{escape(scenario.what_to_watch)}</p>
  </div>
</div>
{attacks}
{validator_panel(validator, show_fixed=scenario.fixed)}
<div class="nav">
  <span>{f'<a class="btn" href="/scenario/{previous.id}">&larr; {escape(previous.title)}</a>' if previous else ""}</span>
  <span>{f'<a class="btn" href="/scenario/{following.id}">{escape(following.title)} &rarr;</a>' if following else ""}</span>
</div>
"""
    response = html(page(f"{scenario.title} - CSRF lab", body, site_bar=_bar(req)))
    for name, value in headers:
        response.with_header(name, value)
    return response


def attack_links(req: Request, scenario: scen.Scenario) -> str:
    from .evil import ATTACKS, attack_url

    rows = []
    for attack_id in scenario.attacks:
        attack = ATTACKS.get(attack_id)
        if not attack:
            continue
        url = attack_url(req, attack)
        rows.append(
            f'<tr><td><a class="btn danger" href="{escape(url)}">{escape(attack.label)}</a></td>'
            f"<td>{escape(attack.description)}</td>"
            f'<td class="note">{escape(attack.expectation)}</td></tr>'
        )
    extra = ""
    if scenario.id == "b3-token-not-session-bound":
        extra = (
            '<p class="note" style="margin-top:14px">First, '
            '<a href="/demo/attacker-token">get a token the way an attacker would</a>.</p>'
        )
    return (
        '<div class="panel"><h3>Attacks to run from the attacker site</h3>'
        "<table><tr><th>Launch</th><th>What it does</th><th>Expected</th></tr>"
        + "".join(rows)
        + "</table>"
        + extra
        + f'<p class="note" style="margin-top:14px">Or open the '
        f'<a href="{escape(req.config.evil_origin)}/tweaker">request tweaker</a> to change '
        "any part of the forged request by hand.</p></div>"
    )


def attacker_token(req: Request) -> Response:
    token = req.state.mint_pool_token()
    evil_url = f"{req.config.evil_origin}/attack/pool_token_post?token={token}"
    body = f"""
<h1>A token the attacker obtained legitimately</h1>
<p class="sub">This stands in for the attacker logging into their own account on the bank
and keeping the token they were issued.</p>
<div class="panel"><pre>{escape(token)}</pre></div>
<p>The server has added this to its pool of issued tokens. It belongs to no session in
particular, which is the entire flaw.</p>
<p><a class="btn danger" href="{escape(evil_url)}">Use this token in the attack</a>
<a class="btn" href="/scenario/b3-token-not-session-bound">Back to the scenario</a></p>
"""
    return html(page("Attacker token", body, site_bar=_bar(req)))


def code_page(req: Request, name: str) -> Response:
    validator = VALIDATORS.get(name)
    if not validator:
        return not_found()
    body = f"""
<h1>{escape(validator.label)}</h1>
<p class="sub">{escape(validator.summary.splitlines()[0] if validator.summary else "")}</p>
{validator_panel(validator, show_fixed=True)}
<p><a class="btn" href="/scenario/{escape(req.state.current_scenario_id or scen.DEFAULT_SCENARIO_ID)}">Back to the scenario</a></p>
"""
    return html(page(validator.label, body, site_bar=_bar(req)))


# --------------------------------------------------------------------------------------
# The endpoint under attack
# --------------------------------------------------------------------------------------


def change_email(req: Request) -> Response:
    scenario = current_scenario(req)
    session = find_session(req)
    validator = VALIDATORS[scenario.validator]
    ctx = RequestContext(
        method=req.method,
        path=req.path,
        query=req.query,
        form=req.form,
        headers=req.headers,
        cookies=req.cookies,
        raw_request=req.raw,
        config=req.config,
        scenario=scenario,
        state=req.state,
        session=session,
    )

    email_before = req.state.email
    requested = ctx.param("email") or ""
    status = 200

    if ctx.effective_method in SAFE_METHODS and not scenario.allow_get_mutation and not scenario.fixed:
        verdict = Verdict.block(
            Layer.METHOD,
            f"This endpoint does not change state on {ctx.effective_method}. There is no "
            "state-changing GET for an attacker to reach.",
        )
        status = 405
    elif session is None:
        reason = (
            "The browser did not send the session cookie, so the bank saw an anonymous "
            "request and rejected it. The application's own CSRF check never ran."
        )
        if scenario.fixed:
            reason += (
                " In this scenario the token and Origin checks would have rejected it as well - "
                "the cookie attribute is the outermost layer, not the only one."
            )
        verdict = Verdict.block(Layer.BROWSER_COOKIE, reason)
        status = 403
    else:
        verdict = validator(ctx)
        status = 200 if verdict.allowed else 403

    if verdict.allowed and requested:
        req.state.set_email(requested)

    email_after = req.state.email
    response_headers = [("Content-Type", "text/html; charset=utf-8")]
    attempt = req.state.record(
        {
            "scenario_id": scenario.id,
            "scenario_title": scenario.title,
            "raw_request": req.raw,
            "status": status,
            "response_headers": response_headers,
            "verdict": verdict,
            "email_before": email_before,
            "email_after": email_after,
            "validator_name": validator.name,
        }
    )

    previous, following = scen.neighbours(scenario.id)
    body = f"""
<p class="note">{escape(scenario.track)} &middot; attempt #{attempt.number}</p>
<h1>{escape(scenario.title)}</h1>
{verdict_banner(verdict, attempt.changed_state, email_after)}
<div class="panel tight">
  <dl class="kv">
    <dt>Account email before</dt><dd>{escape(email_before)}</dd>
    <dt>Account email after</dt><dd>{escape(email_after)}</dd>
    <dt>Requested value</dt><dd>{escape(requested) or "(none)"}</dd>
  </dl>
</div>
{exchange_panel(attempt, ctx, verdict)}
{validator_panel(validator, show_fixed=scenario.fixed)}
<div class="panel tight">
  <p><a class="btn" href="/scenario/{scenario.id}">Back to this scenario</a>
  <a class="btn" href="/reset">Reset the account email</a>
  <a class="btn" href="{escape(req.config.evil_origin)}/attack-menu">Attacker site</a>
  {f'<a class="btn primary" href="/scenario/{following.id}">Next: {escape(following.title)} &rarr;</a>' if following else ""}</p>
</div>
"""
    response = html(page(f"Attempt #{attempt.number}", body, site_bar=_bar(req)), status=status)
    return response


def log_page(req: Request) -> Response:
    rows = []
    for attempt in reversed(req.state.attempts):
        outcome = (
            '<span style="color:#ff6b6b">succeeded</span>'
            if attempt.verdict.allowed
            else f'<span style="color:#4ade80">blocked by {escape(attempt.verdict.layer)}</span>'
        )
        rows.append(
            f"<tr><td>#{attempt.number}</td><td>{escape(attempt.scenario_title)}</td>"
            f"<td>{attempt.status}</td><td>{outcome}</td>"
            f"<td>{escape(attempt.email_before)} &rarr; {escape(attempt.email_after)}</td></tr>"
        )
    body = f"""
<h1>Attempt log</h1>
<p class="sub">Every request this lab has handled, newest first. Useful for scrolling back
during questions.</p>
<div class="panel"><table>
<tr><th>#</th><th>Scenario</th><th>Status</th><th>Outcome</th><th>Account email</th></tr>
{"".join(rows) or '<tr><td colspan="5" class="note">Nothing yet.</td></tr>'}
</table></div>
"""
    return html(page("Attempt log", body, site_bar=_bar(req)))


# --------------------------------------------------------------------------------------
# Self-check
# --------------------------------------------------------------------------------------

PROBE_COOKIES = ("probe_none", "probe_lax", "probe_strict")


def self_check(req: Request) -> Response:
    config = req.config
    results = req.state.probe_results

    def row(kind: str, label: str, expectation: str) -> str:
        result = results.get(kind)
        if not result:
            return f'<tr><td>{escape(label)}</td><td class="note">not run yet</td><td class="note">{escape(expectation)}</td></tr>'
        arrived = ", ".join(result["cookies"]) or "none"
        return (
            f"<tr><td>{escape(label)}</td>"
            f"<td><code>{escape(arrived)}</code><br><span class='note'>Sec-Fetch-Site: "
            f"{escape(result['sec_fetch_site'] or 'absent')}</span></td>"
            f'<td class="note">{escape(expectation)}</td></tr>'
        )

    cross = results.get("cross-site-fetch") or results.get("cross-site-post")
    sibling = results.get("same-site-fetch")
    premise = '<p class="note">Run the probes below, then this box will tell you whether the lab can teach honestly on this browser.</p>'
    if cross:
        leaked = [name for name in cross["cookies"] if name in ("probe_lax", "probe_strict")]
        if leaked:
            premise = (
                f'<div class="bad-box"><b>This browser treats {escape(config.hosts["evil"])} and '
                f"{escape(config.hosts['bank'])} as the same site.</b> A cross-site request "
                f"carried {escape(', '.join(leaked))}, which should have been withheld. Every "
                "SameSite lesson in this lab would be wrong here. Switch host sets: restart with "
                "<code>--hosts=test</code> (and add the /etc/hosts entry) or "
                "<code>--hosts=localhost</code>, then re-run this page.</div>"
            )
        else:
            premise = (
                '<div class="panel" style="border-color:#2c5e3f"><b>Premise confirmed.</b> '
                "Lax and Strict cookies were withheld on a cross-site request, so the two "
                "origins really are different sites on this browser."
            )
            if sibling:
                shares = [name for name in sibling["cookies"] if name in ("probe_lax", "probe_strict")]
                premise += (
                    f" The sibling host {escape(config.hosts['uploads'])} "
                    + (
                        f"shares cookies ({escape(', '.join(shares))}), so the same-site gadget "
                        "scenarios will work as described."
                        if shares
                        else "did not share cookies, which is unexpected - the sibling-domain "
                        "scenarios may not demonstrate what they claim."
                    )
                )
            premise += "</div>"

    body = f"""
<h1>Self-check</h1>
<p class="sub">Run this before you present. It reports what your browser actually does
rather than what the lab assumes.</p>
<div class="panel tight">
  <h3>Origin capabilities</h3>
  <p>{capability_pills(config)}</p>
  <dl class="kv">
    <dt>Scheme</dt><dd>{escape(config.scheme)}</dd>
    <dt>Trustworthy origin</dt><dd>{"yes" if config.trustworthy_origin else "no"}</dd>
    <dt>Bank</dt><dd>{escape(config.bank_origin)}</dd>
    <dt>Attacker</dt><dd>{escape(config.evil_origin)}</dd>
    <dt>Bank's sibling</dt><dd>{escape(config.uploads_origin)}</dd>
  </dl>
  {"".join(f'<div class="warn-box">{escape(note)}</div>' for note in config.degradations())}
</div>
{premise}
<div class="panel">
  <h3>Cookie probes</h3>
  <p class="note">Three cookies have just been set on the bank, one at each SameSite level.
  The frames below make real requests to the bank from the attacker site and from the
  bank's sibling host, and the bank records which cookies arrived.</p>
  <table>
    <tr><th style="width:280px">Request</th><th>Cookies that arrived</th><th>Expected</th></tr>
    {row("same-origin-fetch", "Same-origin fetch (from the bank)", "all three")}
    {row("same-site-fetch", f"Same-site fetch (from {config.hosts['uploads']})", "all three; the Lax and Strict pair is what proves the sibling shares the site")}
    {row("cross-site-fetch", f"Cross-site fetch (from {config.hosts['evil']})", "probe_none only")}
    {row("cross-site-post", f"Cross-site form POST (from {config.hosts['evil']})", "probe_none only")}
  </table>
  <p style="margin-top:14px"><a class="btn primary" href="/self-check">Refresh results</a></p>
</div>
<div style="opacity:.25;font-size:12px">
  <iframe src="/self-check/probe-frame" style="width:100%;height:60px;border:0"></iframe>
  <iframe src="{escape(config.uploads_origin)}/probe" style="width:100%;height:60px;border:0"></iframe>
  <iframe src="{escape(config.evil_origin)}/probe" style="width:100%;height:120px;border:0"></iframe>
</div>
<p><a class="btn" href="/">Back to the bank</a></p>
"""
    response = html(page("Self-check", body, site_bar=_bar(req)))
    samesite_values = {"probe_none": "None", "probe_lax": "Lax", "probe_strict": "Strict"}
    for name, samesite in samesite_values.items():
        if samesite == "None" and not config.samesite_none_available:
            continue
        response.with_header("Set-Cookie", _cookie(name, "1", samesite, config, http_only=False))
    return response


def self_check_hit(req: Request) -> Response:
    kind = req.q("kind", "unknown")
    req.state.record_probe(
        kind,
        {
            "cookies": [name for name in PROBE_COOKIES if name in req.cookies],
            "sec_fetch_site": req.headers.get("sec-fetch-site"),
        },
    )
    response = Response(status=204, body=b"")
    # So the cross-site fetch is not rejected before it is recorded.
    response.with_header("Access-Control-Allow-Origin", "*")
    return response


def probe_frame(req: Request) -> Response:
    """Same-origin probe, served from the bank itself."""
    body = f"""<!doctype html><meta charset="utf-8">
<body style="font:12px sans-serif;color:#888;background:#111">same-origin probe
<script>
fetch("/self-check/hit?kind=same-origin-fetch", {{credentials:"include"}});
</script></body>"""
    return html(body.encode())
