"""The scenarios, in presentation order.

Each one reconfigures the bank: which SameSite value the session cookie carries, which
validator runs, whether a state-changing GET exists, and whether method override is
honoured. The prose here is what the room reads, so it carries the lesson.
"""

from __future__ import annotations

import dataclasses


@dataclasses.dataclass(frozen=True)
class Scenario:
    id: str
    track: str
    title: str
    subtitle: str
    validator: str
    cookie_samesite: str  # "None" | "Lax" | "Strict"
    attacks: tuple[str, ...]
    explanation: str
    what_to_watch: str
    allow_get_mutation: bool = False
    method_override_enabled: bool = False
    renders_token_field: bool = False
    sets_csrf_cookie: bool = False
    sets_csrf_key_cookie: bool = False
    requires_samesite_none: bool = False
    fixed: bool = False
    # Shown as a prominent toggle on the scenario page.
    offers_samesite_toggle: bool = False

    @property
    def cookie_samesite_effective(self) -> str:
        return self.cookie_samesite


TRACK_A = "Track A - the classic bug"
TRACK_B = "Track B - fixes that only look like fixes"
TRACK_C = "Track C - SameSite bypasses"
TRACK_X = "The one to build the session around"
TRACK_FIXED = "The fix"


SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        id="a1-tokenless-post",
        track=TRACK_A,
        title="Tokenless form POST",
        subtitle="The textbook CSRF bug, as it behaved before SameSite defaults",
        validator="no_validation",
        cookie_samesite="None",
        requires_samesite_none=True,
        attacks=("form_post",),
        explanation=(
            "The bank changes the account email on POST and checks nothing but the session "
            "cookie. The attacker's page auto-submits a form to the bank, the browser "
            "attaches the cookie because this cookie is explicitly SameSite=None, and the "
            "bank cannot tell the difference between this and the user clicking their own "
            "Save button. This is PortSwigger's baseline: a relevant action, cookie-based "
            "session handling, and no unpredictable parameter."
        ),
        what_to_watch=(
            "The Cookie header is present on a request that came from another site, and the "
            "server ran no check at all. Note that reproducing this in a current browser "
            "required setting SameSite=None on purpose - the browser default would have "
            "stopped it, which is exactly why the next two scenarios matter."
        ),
    ),
    Scenario(
        id="a2-state-changing-get",
        track=TRACK_A,
        title="State-changing GET",
        subtitle="Survives SameSite=Lax, which is why 'we set SameSite' is not a fix",
        validator="no_validation",
        cookie_samesite="Lax",
        allow_get_mutation=True,
        attacks=("get_nav",),
        explanation=(
            "Same endpoint, but the email can also be changed with a GET, and the session "
            "cookie is now SameSite=Lax - the modern browser default. Lax still sends the "
            "cookie on a top-level navigation that uses a safe method, so a link is enough. "
            "OWASP calls a state-changing GET the single most common way SameSite-based "
            "defenses fail in practice."
        ),
        what_to_watch=(
            "The cookie arrives even though the request came from another site, because this "
            "is a top-level GET navigation. A cross-site fetch or an <img> tag would not have "
            "carried it. The defense is doing exactly what it promises and the bug is still "
            "exploitable."
        ),
    ),
    Scenario(
        id="a3-samesite-only",
        track=TRACK_A,
        title="SameSite alone, no token",
        subtitle="The cross-site POST fails, and nothing on the server changed",
        validator="no_validation",
        cookie_samesite="Lax",
        attacks=("form_post", "get_nav_blocked"),
        explanation=(
            "The GET route is gone and the cookie is SameSite=Lax, so the forged POST fails. "
            "The server still has no CSRF check whatsoever. This is a real improvement and a "
            "dangerous place to stop: the protection lives entirely in the visitor's browser, "
            "so it does not apply to users on browsers that do not enforce SameSite, and it "
            "evaporates the moment someone adds a GET route or a method override."
        ),
        what_to_watch=(
            "There is no Cookie header on the forged request. The browser withheld it, so the "
            "bank saw an unauthenticated request. Read the verdict line carefully: the layer "
            "that stopped this was the browser, not the application."
        ),
    ),
    Scenario(
        id="b1-token-skipped-on-get",
        track=TRACK_B,
        title="Token enforced on POST, skipped on GET",
        subtitle="A real token, a real check, and a GET route that bypasses both",
        validator="token_checked_on_post_only",
        cookie_samesite="Lax",
        allow_get_mutation=True,
        renders_token_field=True,
        attacks=("get_nav", "form_post"),
        explanation=(
            "The bank now issues a session-bound token and validates it. Try the forged POST "
            "first: it is rejected, and a reviewer would call this fixed. Then send a GET. The "
            "validation branch only runs for POST, so the token is never looked at, and Lax "
            "happily attaches the cookie to a top-level navigation."
        ),
        what_to_watch=(
            "Compare the two attempts. The POST is blocked by the token check. The GET is "
            "allowed with the token check skipped entirely, and the reason line says so. The "
            "token was never the problem; the method-dependent branch was."
        ),
    ),
    Scenario(
        id="b2-token-skipped-when-omitted",
        track=TRACK_B,
        title="Token validated only when the parameter is present",
        subtitle="A wrong token is rejected; an absent one is not",
        validator="token_checked_when_present",
        cookie_samesite="None",
        requires_samesite_none=True,
        renders_token_field=True,
        attacks=("form_post_wrong_token", "form_post_omit_token"),
        explanation=(
            "Two attacks here, and the order matters. Send a wrong token and the bank rejects "
            "it, which is the negative test almost every team writes. Then omit the csrf "
            "parameter entirely. The validation function returns early when the parameter is "
            "missing, so the request sails through. A test suite that only ever sends a bad "
            "value will report this endpoint as protected forever."
        ),
        what_to_watch=(
            "The two requests differ by one absent form field, and the outcomes are opposite. "
            "This is the single most useful thing to show a team that has just finished adding "
            "tokens: prove your check rejects the missing case, not just the wrong case."
        ),
    ),
    Scenario(
        id="b3-token-not-session-bound",
        track=TRACK_B,
        title="Token not tied to the session",
        subtitle="Any token the server ever issued is accepted",
        validator="token_from_global_pool",
        cookie_samesite="None",
        requires_samesite_none=True,
        renders_token_field=True,
        attacks=("pool_token_post",),
        explanation=(
            "The bank validates that the token is one it issued, but keeps a single global "
            "pool instead of comparing against the token stored in this user's session. The "
            "attacker logs into their own account, keeps their own perfectly valid token, and "
            "sends it alongside the victim's cookie. Grab a token from the link below first - "
            "that stands in for the attacker logging in as themselves."
        ),
        what_to_watch=(
            "The token in the request body is valid and completely unrelated to the session in "
            "the Cookie header. The server never compares the two. OWASP's requirement that a "
            "token be 'unique per user session' is precisely this."
        ),
    ),
    Scenario(
        id="b4-token-tied-to-non-session-cookie",
        track=TRACK_B,
        title="Token tied to a non-session cookie",
        subtitle="Two components, one for sessions and one for CSRF, not integrated",
        validator="token_tied_to_non_session_cookie",
        cookie_samesite="None",
        requires_samesite_none=True,
        renders_token_field=True,
        sets_csrf_key_cookie=True,
        attacks=("inject_csrfkey_cookie_then_post",),
        explanation=(
            "The token is bound to a csrfKey cookie rather than to the session. Anything that "
            "can write a cookie on the parent domain now controls both halves of the check. "
            "The lab's sibling host uploads.bank.* is cross-origin but same-site with the "
            "bank, so it can set a cookie with Domain=bank.* - which is exactly the position a "
            "subdomain takeover or a forgotten staging host puts an attacker in."
        ),
        what_to_watch=(
            "Two requests happen: one to the sibling host to plant the cookie, then the forged "
            "POST carrying a token derived from it. The session cookie is along for the ride "
            "and is never consulted by the CSRF check."
        ),
    ),
    Scenario(
        id="b5-naive-double-submit",
        track=TRACK_B,
        title="Naive double-submit cookie",
        subtitle="Stateless, simple, and defeated by anything that can set a cookie",
        validator="naive_double_submit",
        cookie_samesite="None",
        requires_samesite_none=True,
        renders_token_field=True,
        sets_csrf_cookie=True,
        attacks=("inject_csrf_cookie_then_post",),
        explanation=(
            "The server compares the submitted token to a cookie of the same name and keeps no "
            "record of its own, so the attacker does not need to steal or guess anything. They "
            "invent a value, plant it as a cookie from the sibling host, and submit the same "
            "value in the form. OWASP now labels this pattern DISCOURAGED and recommends a "
            "signed, session-bound variant instead."
        ),
        what_to_watch=(
            "The csrf cookie and the csrf form field match perfectly, and both were chosen by "
            "the attacker. Compare this with the fixed scenario, where the token the server "
            "expects exists only in server-side session state."
        ),
    ),
    Scenario(
        id="b6-referer-dropped",
        track=TRACK_B,
        title="Referer check skipped when the header is absent",
        subtitle="The attacker chooses whether to send a Referer",
        validator="referer_checked_when_present",
        cookie_samesite="None",
        requires_samesite_none=True,
        attacks=("form_post", "form_post_no_referrer"),
        explanation=(
            "Instead of a token, the bank checks that the Referer starts with its own origin, "
            "and skips the check when there is no Referer. Referer is optional and the sending "
            "page controls it: one meta tag suppresses it. Send the plain POST first to see the "
            "check work, then the no-referrer version to see it evaporate."
        ),
        what_to_watch=(
            "The second request has no Referer line at all. The header is a privacy-sensitive "
            "hint, not an authentication signal, and load balancers and proxies strip it in "
            "normal traffic too - which is why teams end up writing the skip-if-absent branch."
        ),
    ),
    Scenario(
        id="b7-referer-naive-match",
        track=TRACK_B,
        title="Referer matched by substring",
        subtitle="The hostname appears in the URL, just not where it matters",
        validator="referer_matched_loosely",
        cookie_samesite="None",
        requires_samesite_none=True,
        attacks=("form_post_loose_referer",),
        explanation=(
            "This time the check requires the bank's hostname to appear in the Referer, which "
            "sounds stricter and is weaker. The attack page is served from a URL whose query "
            "string contains the bank's hostname, with Referrer-Policy: unsafe-url so the full "
            "URL including that query string is sent. A check using startswith instead falls "
            "to the mirror-image trick, a subdomain like bank.test.evil.test."
        ),
        what_to_watch=(
            "Read the Referer line. It is an attacker URL that merely mentions the bank. Any "
            "origin comparison has to be anchored to the whole origin, which is what the fixed "
            "implementation does."
        ),
    ),
    Scenario(
        id="c1-method-override",
        track=TRACK_C,
        title="Method override defeats Lax",
        subtitle="A top-level GET that the framework turns back into a POST",
        validator="no_validation",
        cookie_samesite="Lax",
        method_override_enabled=True,
        attacks=("get_nav_method_override", "form_post"),
        explanation=(
            "There is no state-changing GET here: the endpoint rejects GET outright. But the "
            "framework honours a method override, so a top-level GET navigation carrying "
            "_method=POST becomes a POST after the browser has already decided to attach the "
            "Lax cookie. ASP.NET Core ships HttpMethodOverride middleware, so this is worth a "
            "grep in your own solution rather than a curiosity."
        ),
        what_to_watch=(
            "The request line says GET and the server processed a POST. Lax made its decision "
            "based on the real method; the application made its decision based on a parameter "
            "the attacker controls."
        ),
    ),
    Scenario(
        id="c2-strict-sibling-gadget",
        track=TRACK_C,
        title="Strict defeated by a same-site gadget",
        subtitle="A client-side redirect on a sibling host launders the request",
        validator="no_validation",
        cookie_samesite="Strict",
        allow_get_mutation=True,
        attacks=("direct_get_strict", "server_redirect", "gadget_redirect"),
        explanation=(
            "The cookie is SameSite=Strict, the strongest setting, and a direct cross-site "
            "navigation carries no cookie. The sibling host uploads.bank.* has a client-side "
            "open redirect. Sending the victim there first means the request to the bank is "
            "issued by a page on the bank's own site, so the browser considers it same-site and "
            "attaches even Strict cookies. Try all three buttons in order: direct, then the "
            "server-side redirect, then the client-side gadget."
        ),
        what_to_watch=(
            "Only the third one works, and the difference is where the redirect happened. With "
            "a server-side 302 the browser still remembers the chain started cross-site. With a "
            "client-side redirect the resulting request is an ordinary same-site request. This "
            "is why PortSwigger tells you to audit sibling domains as part of your own attack "
            "surface."
        ),
    ),
    Scenario(
        id="x1-blocked-for-the-wrong-reason",
        track=TRACK_X,
        title="Blocked for the wrong reason",
        subtitle="Looks fixed. Turn SameSite off and find out what was really stopping it.",
        validator="token_checked_when_present",
        cookie_samesite="Lax",
        renders_token_field=True,
        offers_samesite_toggle=True,
        attacks=("form_post_omit_token",),
        explanation=(
            "The bank renders a token, validates it, and rejects the forged POST. Every signal a "
            "reviewer looks at says this endpoint is protected, and the ticket gets closed. "
            "Fire the attack with the cookie on Lax and watch it fail. Then use the toggle to "
            "set the cookie to SameSite=None - changing nothing about the application code - and "
            "fire exactly the same attack again. It succeeds, because the token check was never "
            "reached and would not have stopped it anyway: this validator skips validation when "
            "the parameter is absent."
        ),
        what_to_watch=(
            "In the first attempt the verdict names the browser as the layer that blocked it, and "
            "the token check never ran. Two defects were hiding behind one passing test: the "
            "endpoint has no working token validation, and the only thing protecting it was a "
            "cookie attribute. This is the argument for testing each layer in isolation."
        ),
    ),
    Scenario(
        id="fixed",
        track=TRACK_FIXED,
        title="The fixed implementation",
        subtitle="Session-bound token, anchored Origin check, Fetch Metadata, Strict cookie",
        validator="fully_validated",
        cookie_samesite="Strict",
        renders_token_field=True,
        fixed=True,
        attacks=(
            "form_post",
            "form_post_omit_token",
            "form_post_wrong_token",
            "get_nav",
            "get_nav_method_override",
            "gadget_redirect",
            "inject_csrf_cookie_then_post",
        ),
        explanation=(
            "Every attack from every previous scenario is available here and all of them fail. "
            "The token comes from a CSPRNG, lives in server-side session state, and is compared "
            "in constant time, with a missing token rejected exactly like a wrong one. "
            "Validation runs on every state-changing request regardless of method or content "
            "type. Origin is compared against the full origin, anchored. Sec-Fetch-Site rejects "
            "cross-site requests and fails closed when absent. The cookie is Strict, HttpOnly "
            "and Secure. There is no state-changing GET, so there is nothing for a method "
            "override to reach."
        ),
        what_to_watch=(
            "Each attack is blocked by a named layer, and the legitimate form on the bank's own "
            "page still works. That second half matters: a CSRF defense that breaks the real "
            "form gets reverted within a week, usually with [IgnoreAntiforgeryToken]."
        ),
    ),
)

BY_ID = {scenario.id: scenario for scenario in SCENARIOS}
DEFAULT_SCENARIO_ID = SCENARIOS[0].id


def neighbours(scenario_id: str) -> tuple[Scenario | None, Scenario | None]:
    ids = [s.id for s in SCENARIOS]
    index = ids.index(scenario_id)
    previous = SCENARIOS[index - 1] if index > 0 else None
    following = SCENARIOS[index + 1] if index < len(SCENARIOS) - 1 else None
    return previous, following
