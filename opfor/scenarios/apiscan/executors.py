"""Active-check executors, a self-built templated scanner.

ActiveCheckExecutor runs one request-plus-matcher template. JwtAttackExecutor
runs a small multi-step flow (login, tamper the token, replay against a validate
endpoint), because some classes like JWT need more than a single request. Both
are pure Python, no external tool, and everything that defines an attack lives in
the template data.
"""

from __future__ import annotations

import base64
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

from opfor.model import Fact, Finding, Observation
from opfor.plugins.base import Executor

_TIMEOUT = 12
_BODY_CAP = 4096
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _do(base, method, path, *, body=None, content_type=None, headers=None, follow_redirects=True) -> dict:
    """One HTTP request, raw result, never raises."""
    url = base.rstrip("/") + path
    h = {"User-Agent": "opfor"}
    if content_type:
        h["Content-Type"] = content_type
    h.update(headers or {})
    data = body.encode() if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    chain = [urllib.request.HTTPSHandler(context=_CTX)]
    if follow_redirects is False:
        chain.insert(0, _NoRedirect)
    opener = urllib.request.build_opener(*chain)
    try:
        with opener.open(req, timeout=_TIMEOUT) as resp:
            return {"url": url, "status": resp.status, "headers": dict(resp.headers.items()),
                    "body": resp.read(_BODY_CAP).decode("utf-8", "replace")}
    except urllib.error.HTTPError as exc:
        return {"url": url, "status": exc.code, "headers": dict(exc.headers.items()) if exc.headers else {},
                "body": exc.read(_BODY_CAP).decode("utf-8", "replace")}
    except urllib.error.URLError as exc:
        return {"url": url, "status": None, "headers": {}, "body": "", "error": str(exc.reason)}


def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _matches(match: dict, raw: dict) -> bool:
    if raw.get("error"):
        return False
    body = raw.get("body") or ""
    headers = {k.lower(): str(v) for k, v in (raw.get("headers") or {}).items()}
    if "status" in match and raw.get("status") != match["status"]:
        return False
    for needle in _as_list(match.get("body_contains")):
        if needle not in body:
            return False
    for needle in _as_list(match.get("body_not_contains")):
        if needle in body:
            return False
    if "body_regex" in match and not re.search(match["body_regex"], body):
        return False
    hc = match.get("header_contains")
    if hc and str(hc["value"]).lower() not in headers.get(str(hc["name"]).lower(), "").lower():
        return False
    return True


def _emit(entrypoint_id: str, raw: dict, template: dict) -> list[Fact]:
    tid = template.get("id", "check")
    if not _matches(template.get("match", {}), raw):
        return [Fact(kind="check-clean", about=entrypoint_id, data={"id": tid})]
    finding = Finding(
        id=f"finding:{tid}:{urllib.parse.urlsplit(raw.get('url') or '').netloc}",
        props={
            "title": template.get("title", tid),
            "severity": template.get("severity", "info"),
            "domain": urllib.parse.urlsplit(raw.get("url") or "").netloc,
            "url": raw.get("url"),
            "evidence": f"{tid} fired at {raw.get('url')} (status {raw.get('status')})",
            "status": raw.get("status"),
            "body_snippet": (raw.get("body") or "")[:240],
        },
    )
    return [Fact(kind="vuln", about=entrypoint_id, data={"id": tid, "severity": template.get("severity")}, yields=(finding,))]


class ActiveCheckExecutor(Executor):
    capability = "active_check"

    def run(self, task, graph) -> Observation:
        tpl = task.params["template"]
        r = tpl.get("request", {})
        raw = _do(
            task.params["base_url"], r.get("method", "GET").upper(), r.get("path", "/"),
            body=r.get("body"), content_type=r.get("content_type"),
            headers=r.get("headers"), follow_redirects=r.get("follow_redirects", True),
        )
        raw["template"] = tpl
        return Observation(entrypoint_id=task.id, action="active_check", raw=raw)

    def perceive(self, observation) -> list[Fact]:
        return _emit(observation.entrypoint_id, observation.raw, observation.raw.get("template", {}))


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _tamper(token: str, mode: str) -> str:
    parts = token.split(".")
    if mode == "alg_none":
        header = _b64url(b'{"typ":"JWT","alg":"none"}')
        return f"{header}.{parts[1]}." if len(parts) >= 2 else token
    # default: tamper_signature, flip the last few chars so the signature is wrong
    if len(parts) >= 3 and parts[2]:
        sig = parts[2]
        flipped = sig[:-3] + ("aaa" if not sig.endswith("aaa") else "bbb")
        return f"{parts[0]}.{parts[1]}.{flipped}"
    return token


class JwtAttackExecutor(Executor):
    capability = "jwt_attack"

    def run(self, task, graph) -> Observation:
        tpl = task.params["template"]
        base = task.params["base_url"]
        login = tpl["login"]
        lr = _do(base, "POST", login["path"], body=json.dumps(login["body"]), content_type="application/json")
        token = None
        try:
            token = json.loads(lr["body"]).get(login.get("token_field", "token"))
        except Exception:
            token = None
        if not token:
            token = lr.get("headers", {}).get("Authorization") or lr.get("headers", {}).get("authorization")
        if not token:
            raw = {"url": base + tpl["validate"]["path"], "error": "no token from login", "template": tpl, "status": lr["status"]}
            return Observation(entrypoint_id=task.id, action="jwt_attack", raw=raw)
        forged = _tamper(token, tpl.get("attack", "tamper_signature"))
        vr = _do(base, "GET", tpl["validate"]["path"], headers={"Authorization": forged})
        vr["template"] = tpl
        return Observation(entrypoint_id=task.id, action="jwt_attack", raw=vr)

    def perceive(self, observation) -> list[Fact]:
        return _emit(observation.entrypoint_id, observation.raw, observation.raw.get("template", {}))


def default_executors() -> dict:
    return {"active_check": ActiveCheckExecutor(), "jwt_attack": JwtAttackExecutor()}
