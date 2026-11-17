"""HTML shell and shared components. Sized for a projector: large type, high contrast."""

from __future__ import annotations

from html import escape

from .state import Layer
from .validators import Validator

CSS = """
:root {
  --bg: #12161c;
  --panel: #1b212b;
  --panel-2: #222a36;
  --ink: #e8edf4;
  --muted: #9aa7b8;
  --line: #313c4b;
  --bad: #ff6b6b;
  --good: #4ade80;
  --warn: #fbbf24;
  --accent: #60a5fa;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--ink);
  font: 18px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
.wrap { max-width: 1180px; margin: 0 auto; padding: 24px 28px 80px; }
a { color: var(--accent); }
h1 { font-size: 34px; line-height: 1.2; margin: 6px 0 4px; }
h2 { font-size: 24px; margin: 32px 0 12px; }
h3 { font-size: 19px; margin: 22px 0 8px; }
.sub { color: var(--muted); font-size: 19px; margin: 0 0 22px; }
.site-bar {
  display: flex; align-items: center; gap: 14px; flex-wrap: wrap;
  padding: 10px 28px; border-bottom: 1px solid var(--line); background: var(--panel);
  font-size: 15px;
}
.site-bar .tag { font-weight: 700; letter-spacing: .04em; text-transform: uppercase; font-size: 13px; }
.tag.bank { color: var(--good); }
.tag.evil { color: var(--bad); }
.tag.uploads { color: var(--warn); }
.panel {
  background: var(--panel); border: 1px solid var(--line);
  border-radius: 10px; padding: 18px 20px; margin: 16px 0;
}
.panel.tight { padding: 12px 16px; }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
@media (max-width: 980px) { .grid { grid-template-columns: 1fr; } }
pre {
  background: #0d1117; border: 1px solid var(--line); border-radius: 8px;
  padding: 14px 16px; overflow-x: auto; font-size: 15px; line-height: 1.55;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace; margin: 0;
}
pre .hl { background: rgba(251, 191, 36, .18); display: block; }
pre .flaw { background: rgba(255, 107, 107, .20); display: block; }
pre .dim { color: var(--muted); }
.verdict { border-radius: 10px; padding: 18px 22px; margin: 18px 0; border: 2px solid; }
.verdict.ok { border-color: var(--bad); background: rgba(255, 107, 107, .10); }
.verdict.blocked { border-color: var(--good); background: rgba(74, 222, 128, .10); }
.verdict h2 { margin: 0 0 6px; font-size: 26px; }
.verdict .layer { font-size: 17px; color: var(--muted); }
.verdict .layer b { color: var(--ink); }
.btn {
  display: inline-block; padding: 11px 16px; border-radius: 8px; text-decoration: none;
  border: 1px solid var(--line); background: var(--panel-2); color: var(--ink);
  font-size: 16px; margin: 4px 6px 4px 0; cursor: pointer;
}
.btn:hover { border-color: var(--accent); }
.btn.danger { border-color: #7f2c2c; background: #2a1618; color: #ffb4b4; }
.btn.primary { border-color: #2f5d8f; background: #16293f; }
.kv { display: grid; grid-template-columns: 220px 1fr; gap: 6px 16px; font-size: 16px; }
.kv dt { color: var(--muted); }
.kv dd { margin: 0; font-family: ui-monospace, Menlo, monospace; }
.note { color: var(--muted); font-size: 16px; }
.warn-box {
  border-left: 4px solid var(--warn); background: rgba(251, 191, 36, .08);
  padding: 12px 16px; margin: 16px 0; border-radius: 0 8px 8px 0;
}
.bad-box {
  border-left: 4px solid var(--bad); background: rgba(255, 107, 107, .08);
  padding: 12px 16px; margin: 16px 0; border-radius: 0 8px 8px 0;
}
table { border-collapse: collapse; width: 100%; font-size: 16px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); }
th { color: var(--muted); font-weight: 600; }
.nav { display: flex; justify-content: space-between; gap: 12px; margin: 30px 0 0; }
.scenario-list a { display: block; padding: 7px 0; border-bottom: 1px solid var(--line); }
.scenario-list .track { color: var(--muted); font-size: 14px; text-transform: uppercase;
  letter-spacing: .05em; margin: 18px 0 4px; }
.current { color: var(--warn); font-weight: 700; }
label { display: block; margin: 12px 0 4px; font-size: 16px; color: var(--muted); }
select, input[type=text] {
  width: 100%; padding: 9px 11px; border-radius: 7px; border: 1px solid var(--line);
  background: #0d1117; color: var(--ink); font-size: 16px;
  font-family: ui-monospace, Menlo, monospace;
}
.row { display: grid; grid-template-columns: 1fr 1fr; gap: 0 18px; }
@media (max-width: 760px) { .row { grid-template-columns: 1fr; } }
.pill {
  display: inline-block; padding: 3px 9px; border-radius: 999px; font-size: 14px;
  border: 1px solid var(--line); color: var(--muted); margin-right: 6px;
}
.pill.on { color: var(--good); border-color: #2c5e3f; }
.pill.off { color: var(--bad); border-color: #6d2b2b; }
"""


def page(title: str, body: str, site: str = "bank", site_bar: str = "") -> bytes:
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)}</title><style>{CSS}</style></head>
<body>{site_bar}<div class="wrap">{body}</div></body></html>""".encode()


def site_bar(config, role: str, extra: str = "") -> str:
    labels = {
        "bank": ("bank", "VICTIM BANK"),
        "evil": ("evil", "ATTACKER SITE"),
        "uploads": ("uploads", "BANK'S SIBLING HOST"),
    }
    cls, label = labels[role]
    return (
        f'<div class="site-bar"><span class="tag {cls}">{label}</span>'
        f'<code>{escape(config.origin(role))}</code>{extra}</div>'
    )


def verdict_banner(verdict, changed: bool, email_after: str) -> str:
    if verdict.allowed:
        return (
            '<div class="verdict ok"><h2>Attack succeeded</h2>'
            f'<div class="layer">Nothing stopped it. The account email is now '
            f"<b>{escape(email_after)}</b>.</div>"
            f'<div class="layer" style="margin-top:8px">{escape(verdict.reason)}</div></div>'
        )
    detail = "The account email was not changed."
    if changed:  # pragma: no cover - defensive
        detail = "State changed anyway, which would be a bug in the lab."
    return (
        '<div class="verdict blocked"><h2>Attack blocked</h2>'
        f'<div class="layer">Stopped by <b>{escape(verdict.layer)}</b>. {detail}</div>'
        f'<div class="layer" style="margin-top:8px">{escape(verdict.reason)}</div></div>'
    )


def validator_panel(validator: Validator, show_fixed: bool = False) -> str:
    """The code that produced the verdict, with the flawed lines marked."""
    lines = validator.source.rstrip("\n").split("\n")
    rendered = []
    for line in lines:
        marked = any(flaw in line for flaw in validator.flaws)
        cls = "flaw" if marked else None
        text = escape(line)
        rendered.append(f'<span class="{cls}">{text}</span>' if cls else text)
    flaw_note = (
        '<p class="note">The highlighted line is the flaw. Everything else is a reasonable '
        "implementation, which is what makes these bugs survive review.</p>"
        if validator.flaws
        else ""
    )
    fixed_link = (
        '<p class="note"><a href="/code/fully_validated">Compare against the fixed version</a></p>'
        if not show_fixed
        else ""
    )
    return (
        f'<div class="panel"><h3>The check that ran: {escape(validator.label)}</h3>'
        f'<pre>{chr(10).join(rendered)}</pre>{flaw_note}{fixed_link}</div>'
    )


def capability_pills(config) -> str:
    def pill(label: str, ok: bool) -> str:
        return f'<span class="pill {"on" if ok else "off"}">{escape(label)}: {"yes" if ok else "no"}</span>'

    return (
        pill("SameSite=None usable", config.samesite_none_available)
        + pill("Sec-Fetch-* sent", config.fetch_metadata_available)
        + pill("__Host- prefix", config.host_prefix_available)
    )
