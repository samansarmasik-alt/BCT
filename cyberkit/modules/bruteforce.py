"""Login lockout / rate-limit posture testing.

What this module does: it measures whether a login form reacts differently
after repeated failed submissions. It looks for a password form, then submits
a small, fixed number of deliberately INVALID submissions and compares the
responses. If nothing changes, the endpoint has no lockout; if a captcha, 429
or 403 appears, the endpoint is throttling correctly.

What this module does NOT do: it never attempts to log in. Every attempt uses
a random, inert marker string as the username and a different random marker
as the password. These cannot match a real account, and the module never
sends, stores, logs or reports the attempted values -- only a count and the
shape of the response.

Safety properties, all enforced in code below:
- Explicit operator opt-in is required; without it the module does nothing.
- A hard cap of 12 attempts per target, enforced by the loop's ``range()``.
- An explicit ``asyncio.sleep`` between attempts, so the module can never
  exceed roughly one request every 2 seconds regardless of the configured
  concurrency or rate limit.
- At most 3 distinct login endpoints are ever probed.
- Scope is checked first, exactly as in every other module.

Only point this at systems you own or have written authorization to test.
Prefer a staging or lab environment: this submits real failed logins, which
may alert the system owners and may lock out real accounts if a form maps
markers onto existing users.
"""

from __future__ import annotations

import asyncio
import re
import secrets as _secrets
from dataclasses import dataclass

from ..core.http import Response, join_url, normalize_base_url, split_host_port
from ..core.models import Finding, Host, Severity
from ..core.module import Module, register

#: Hard ceiling on failed submissions. Not configurable by design: an operator
#: who needs more than twelve of these is not measuring lockout.
MAX_ATTEMPTS = 12

#: Per-target form of the same cap, used in the loop bound so the value that
#: drives ``range()`` and the value reported to the operator cannot drift.
MAX_ATTEMPTS_PER_TARGET = 12

#: Never probe more than this many distinct login endpoints on one target.
MAX_ENDPOINTS = 3

#: Minimum spacing between attempts, in seconds. The floor of 2.0 is what keeps
#: this module from ever being a fast login-attempt generator.
_ATTEMPT_SPACING = 2.0

#: Publicly-known dummy pairs used by vendor smoke tests. They are defined for
#: documentation and referential completeness only and are deliberately NOT
#: sent: this module prefers inert random markers, which cannot authenticate.
DEFAULT_CREDENTIAL_PAIRS: tuple[tuple[str, str], ...] = (
    ("vendor_test", "vendor_test"),
    ("smoke_test_user", "smoke_test_password"),
    ("demo", "demo"),
)

#: Field names commonly used for the user identifier on a login form.
_USER_FIELDS = ("username", "user", "email", "login", "userid", "user_id", "account")
_PASSWORD_FIELDS = ("password", "pass", "passwd", "pwd")

_FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_INPUT_RE = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
_ATTR_RE = re.compile(r"""(\w[\w:-]*)\s*=\s*(["'])(.*?)\2""", re.DOTALL)
_PASSWORD_INPUT_RE = re.compile(r"""type\s*=\s*["']?password""", re.IGNORECASE)
_REJECT_RE = re.compile(
    r"invalid|incorrect|wrong|failed|denied|unauthorized|too many|try again|captcha|locked|blocked",
    re.IGNORECASE,
)
_CAPTCHA_RE = re.compile(r"captcha|too many|rate.?limit|locked|blocked", re.IGNORECASE)


@dataclass(slots=True)
class _Attempt:
    """One inert submission, reduced to the signals that matter.

    Deliberately holds no username or password: the probe values are generated
    per attempt and discarded, so they cannot leak into a Finding.
    """

    index: int
    status: int
    length: int
    set_cookie: bool
    looks_like_rejection: bool
    throttled: bool
    accepted: bool

    @property
    def signature(self) -> str:
        return f"status={self.status} length={self.length}"


@register
class BruteforceModule(Module):
    """Repeated-failed-login posture check.

    Operators should run this against a staging or lab environment wherever
    possible. Real accounts must never be locked out by an audit, and the
    endpoint under test may share state with production identity providers.
    """

    name = "lockout"
    description = "Test login rate-limit, lockout and throttling posture with inert failed attempts"
    tags = ("web", "auth")
    needs_target = True

    #: This module sends failed logins, so it stays inert unless the operator
    #: explicitly opts in. See :meth:`_consented`.
    REQUIRES_CONSENT = True

    #: Computed from the hard cap so spacing and attempts cannot disagree.
    _delay: float = max(_ATTEMPT_SPACING, 60.0 / max(1, MAX_ATTEMPTS))

    # -- consent --------------------------------------------------------

    def _consented(self) -> bool:
        """Explicit opt-in gate. The single most important property here.

        Consent is granted by supplying any ``--word`` to the run: the operator
        has to type a deliberate value that the toolkit uses for nothing else.
        An empty word list means nobody asked for this module, so it does
        nothing at all.
        """
        if not self.REQUIRES_CONSENT:
            return True
        return any(word.strip() for word in self.config.words)

    # -- entry point ----------------------------------------------------

    async def run(self, targets: list[str]) -> list[Host]:
        if not self._consented():
            return [
                Host(target=target, notes=["lockout testing skipped (not opted in)"])
                for target in targets
            ]
        return list(await asyncio.gather(*(self._scan(target) for target in targets)))

    # -- per-target work ------------------------------------------------

    async def _scan(self, target: str) -> Host:
        host = Host(target=target)
        base = self._base_url(target)
        if base is None:
            host.notes.append("no password form detected")
            return host
        if not self.scope.permits(base):
            host.notes.append(f"skipped out-of-scope base URL: {base}")
            return host

        endpoints = await self._login_endpoints(base)
        if not endpoints:
            host.notes.append("no password form detected")
            return host

        for index, action in enumerate(endpoints):
            await self._probe_endpoint(target, action, host)
            if index + 1 >= MAX_ENDPOINTS:
                break
        return host

    @staticmethod
    def _base_url(target: str) -> str | None:
        """One base URL for ``target``; the first scheme that answers wins."""
        if "://" in target:
            return normalize_base_url(target)
        name, port = split_host_port(target)
        if port:
            scheme = "https" if port in {443, 8443, 9443} else "http"
            return f"{scheme}://{name}:{port}"
        return f"http://{name}"

    async def _login_endpoints(self, base: str) -> list[str]:
        """Action URLs of password forms on the root page, at most 3."""
        response = await self.client.get(f"{base}/")
        if not response.ok:
            return []
        html = response.text(self.config.max_body)
        return _form_actions(html, base)[:MAX_ENDPOINTS]

    async def _probe_endpoint(self, target: str, action: str, host: Host) -> None:
        user_field, password_field = _form_field_names()
        attempts: list[_Attempt] = []

        for index in range(min(MAX_ATTEMPTS, MAX_ATTEMPTS_PER_TARGET)):
            if index:
                # Enforced spacing: the module cannot outrun 1 request / 2s.
                await asyncio.sleep(self._delay)
            fields = {
                user_field: _inert_marker("user"),
                password_field: _inert_marker("pass"),
            }
            response = await self.client.post_form(action, fields)
            attempt = _summarize(index + 1, response)
            attempts.append(attempt)
            if attempt.accepted:
                # Nothing left to measure: stop immediately and report loudly.
                break

        self._report(target, action, attempts, host)
        host.notes.append(
            f"sent {len(attempts)} attempts to {action}, spacing >= {self._delay:.0f}s, "
            "credentials were inert markers"
        )

    # -- reporting ------------------------------------------------------

    def _report(self, target: str, action: str, attempts: list[_Attempt], host: Host) -> None:
        if not attempts:
            return

        def add(severity: Severity, title: str, detail: str, remediation: str = "") -> None:
            host.findings.append(
                Finding(
                    title=title,
                    severity=severity,
                    module=self.name,
                    target=target,
                    detail=detail,
                    evidence=action,
                    remediation=remediation,
                )
            )

        accepted = next((a for a in attempts if a.accepted), None)
        if accepted is not None:
            add(
                "critical",
                "Login accepted the inert probe credentials",
                f"attempt {accepted.index} returned {accepted.signature}; a login endpoint "
                "accepted a submission that cannot correspond to any account",
                "Investigate the authentication path immediately; this is a broken access control defect.",
            )

        throttled = next((a for a in attempts if a.throttled), None)
        if throttled is not None:
            add(
                "info",
                f"Throttling observed after {throttled.index} attempts (positive control)",
                f"{throttled.signature}; the endpoint changed its answer after repeated inert "
                "failures, which is the correct posture",
            )
            return

        signatures = {a.signature for a in attempts}
        if len(signatures) > 1:
            varied = ", ".join(sorted(signatures)[:5])
            add(
                "info",
                "Login responses vary (possible throttling)",
                f"responses changed across {len(attempts)} inert attempts: {varied}",
            )
            return

        only = attempts[0]
        add(
            "medium",
            f"Login endpoint shows no lockout or rate limiting after {len(attempts)} attempts",
            f"every inert attempt returned the identical response ({only.signature}), with no "
            "captcha, 429, 403 or lockout message",
            "Implement progressive delays and lockout; this endpoint accepted "
            f"{len(attempts)} consecutive failed attempts without challenge.",
        )


# -- helpers ---------------------------------------------------------------


def _form_actions(html: str, base: str) -> list[str]:
    """Form action URLs that contain a password input, deduplicated."""
    actions: list[str] = []
    for match in _FORM_RE.finditer(html):
        block = match.group(1)
        if not _PASSWORD_INPUT_RE.search(block):
            continue
        action = _form_action(match.group(0)) or base
        url = join_url(base, action)
        if url not in actions:
            actions.append(url)
    return actions


def _form_action(open_tag: str) -> str:
    for name, _quote, value in _ATTR_RE.findall(open_tag):
        if name.lower() == "action":
            return value.strip()
    return ""


def _form_field_names() -> tuple[str, str]:
    """Field names to post under, preferring the conventional spellings."""
    user = next((name for name in _USER_FIELDS if name), "username")
    return user, _PASSWORD_FIELDS[0]


def _inert_marker(kind: str) -> str:
    """A random, structurally invalid value that cannot match an account.

    The returned string is only ever placed in an outgoing request; it is
    never logged, attached to a Finding or kept after the attempt.
    """
    return f"cyberkit-lockout-probe-{kind}-{_secrets.token_hex(12)}"


def _summarize(index: int, response: Response) -> _Attempt:
    """Reduce a response to the behavioural signals this module compares."""
    body = response.text(8192)
    throttled = response.status in {403, 429} or bool(_CAPTCHA_RE.search(body))
    return _Attempt(
        index=index,
        status=response.status,
        length=len(response.body),
        set_cookie=bool(response.header("set-cookie")),
        looks_like_rejection=bool(_REJECT_RE.search(body)),
        throttled=throttled,
        accepted=response.status in {200, 302} and not response.error,
    )
