"""The bank's sibling host, uploads.bank.*.

Cross-origin with the bank but same-site, which is the whole point. It stands in for any
host on the same registrable domain that an attacker might control: a forgotten staging
box, a subdomain takeover, or user-uploaded content served from a sibling.
"""

from __future__ import annotations

from html import escape
from urllib.parse import quote

from .config import same_origin
from .http_util import Request, Response, html, not_found, redirect
from .ui import page, site_bar


def handle(req: Request) -> Response:
    path = req.path
    if path == "/":
        return home(req)
    if path == "/set-cookie":
        return set_cookie(req)
    if path == "/open-redirect":
        return open_redirect(req)
    if path == "/probe":
        return probe(req)
    return not_found()


def _bar(req: Request) -> str:
    return site_bar(
        req.config,
        "uploads",
        f'<span class="note">Cross-origin with the bank, but same-site: it shares the '
        f'registrable domain {escape(req.config.registrable_domain)}.</span>',
    )


def home(req: Request) -> Response:
    body = f"""
<h1>uploads.bank - sibling host</h1>
<p class="sub">A different origin on the same site as the bank. Same-site, so it can write
cookies the bank will read, and a redirect from here counts as same-site.</p>
<div class="panel">
  <h3>Why this host exists in the lab</h3>
  <p>SameSite is scoped to the registrable domain, not the origin. Anything on
  <code>{escape(req.config.registrable_domain)}</code> is same-site with the bank. This host
  provides the two gadgets the sibling-domain scenarios need: a cookie setter and a
  client-side open redirect.</p>
</div>
"""
    return html(page("Sibling host", body, site_bar=_bar(req)))


def set_cookie(req: Request) -> Response:
    """Set a cookie scoped to the parent domain, then optionally continue.

    Because this host is a subdomain of the bank, a Domain=<registrable> cookie set here is
    sent to the bank. Only the fixed set of names the scenarios use is allowed.
    """
    name = req.q("name")
    value = req.q("value")
    if name not in {"csrf", "csrfKey"}:
        return not_found()
    # The value is attacker-chosen, and it goes straight into a Set-Cookie header. Strip
    # anything that could break out of the header line, or a crafted ?value= could inject
    # arbitrary response headers through this host.
    if not value or any(ch in value for ch in "\r\n\0") or len(value) > 128:
        return not_found()
    domain = req.config.registrable_domain
    cookie = f"{name}={value}; Path=/; Domain={domain}; SameSite=None"
    if req.config.trustworthy_origin:
        cookie += "; Secure"
    response = Response(status=200, body=f"planted {name}={value} for {domain}".encode(),
                        content_type="text/plain; charset=utf-8")
    response.with_header("Set-Cookie", cookie)
    nxt = req.q("next")
    if nxt and same_origin(nxt, req.config.bank_origin):
        return redirect(nxt, [("Set-Cookie", cookie)])
    return response


def open_redirect(req: Request) -> Response:
    """A DOM-based open redirect. The destination comes from the URL fragment.

    The fragment never reaches the server, so this is genuinely client-side: to the browser
    the resulting navigation is an ordinary, standalone, same-site request that carries even
    Strict cookies. The destination is still constrained to the bank origin so the gadget
    cannot be repurposed as a general open redirect.
    """
    bank = req.config.bank_origin
    body = f"""<!doctype html><html><head><meta charset="utf-8"></head>
<body style="font:14px sans-serif;background:#111;color:#ccc">
<p>Client-side redirect gadget on the bank's sibling host.</p>
<script>
  var dest = decodeURIComponent(location.hash.slice(1));
  var allowed = {bank!r};
  if (dest.indexOf(allowed) === 0) {{
    location.replace(dest);
  }} else {{
    document.body.innerHTML += "<p>Destination is not on the bank origin; refusing.</p>";
  }}
</script></body></html>"""
    return html(body.encode())


def probe(req: Request) -> Response:
    """Same-site probe for the self-check: fetches the bank with credentials."""
    bank = req.config.bank_origin
    body = f"""<!doctype html><meta charset="utf-8">
<body style="font:12px sans-serif;color:#888;background:#111">same-site probe (uploads)
<script>
fetch({bank!r}+"/self-check/hit?kind=same-site-fetch", {{credentials:"include",mode:"no-cors"}});
</script></body>"""
    return html(body.encode())
