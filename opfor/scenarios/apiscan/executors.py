"""The active-check executor, a self-built templated scanner.

One executor runs one template (a request plus a matcher) against one target and
emits a Finding when the matcher fires. Everything that defines an attack lives
in the template data, the executor is a generic request-and-match engine, no
external binary. This is our own small nuclei.
"""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

from opfor.model import Fact, Finding, Observation
from opfor.plugins.base import Executor

_TIMEOUT = 12
_BODY_CAP = 4096
# Intentionally lax TLS, these are deliberately broken test targets.
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _request(base: str, req: dict) -> dict:
    """Run the template's request, return raw status/headers/body. Never raises."""
    url = base.rstrip("/") + req.get("path", "/")
    method = req.get("method", "GET").upper()
    data = req["body"].encode() if req.get("body") is not None else None
    headers = {"User-Agent": "opfor"}
    if req.get("content_type"):
        headers["Content-Type"] = req["content_type"]
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    handlers = [urllib.request.HTTPSHandler(context=_CTX)]
    if req.get("follow_redirects") is False:
        handlers.insert(0, _NoRedirect)
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(request, timeout=_TIMEOUT) as resp:
            body = resp.read(_BODY_CAP).decode("utf-8", "replace")
            return {"url": url, "status": resp.status, "headers": dict(resp.headers.items()), "body": body}
    except urllib.error.HTTPError as exc:
        body = exc.read(_BODY_CAP).decode("utf-8", "replace")
        return {"url": url, "status": exc.code, "headers": dict(exc.headers.items()) if exc.headers else {}, "body": body}
    except urllib.error.URLError as exc:
        return {"url": url, "status": None, "headers": {}, "body": "", "error": str(exc.reason)}


def _matches(match: dict, raw: dict) -> bool:
    """Apply a data-defined matcher. Every present condition must hold."""
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


def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


class ActiveCheckExecutor(Executor):
    capability = "active_check"

    def run(self, task, graph) -> Observation:
        template = task.params["template"]
        raw = _request(task.params["base_url"], template.get("request", {}))
        raw["template"] = template
        return Observation(entrypoint_id=task.id, action="active_check", raw=raw)

    def perceive(self, observation) -> list[Fact]:
        raw = observation.raw
        template = raw.get("template", {})
        tid = template.get("id", "check")
        if not _matches(template.get("match", {}), raw):
            return [Fact(kind="check-clean", about=observation.entrypoint_id, data={"id": tid})]
        finding = Finding(
            id=f"finding:{tid}:{raw.get('url')}",
            props={
                "title": template.get("title", tid),
                "severity": template.get("severity", "info"),
                "domain": _host(raw.get("url")),
                "url": raw.get("url"),
                "evidence": f"{tid} fired at {raw.get('url')} (status {raw.get('status')})",
                "status": raw.get("status"),
                "body_snippet": (raw.get("body") or "")[:240],
            },
        )
        return [Fact(kind="vuln", about=observation.entrypoint_id, data={"id": tid, "severity": template.get("severity")}, yields=(finding,))]


def _host(url: str | None) -> str:
    return urllib.parse.urlsplit(url or "").netloc


def default_executors() -> dict:
    return {"active_check": ActiveCheckExecutor()}
