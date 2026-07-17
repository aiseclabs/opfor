"""Identify the product behind a host from its HTTP evidence, with a model.

This is the seam the CVE scan calls to turn raw signals, headers, titles, and version
endpoints, into a product, a version, and a CPE the vulnerability lookup can query. It is
model-backed so it recognizes a novel or obscure product rather than matching a fixed
table, and it stays a seam so the capability that calls it holds no model and no knowledge.
Identifying nothing is a valid answer, an empty product, not an error, so a reply without a
clear product returns empty rather than raising.
"""

from __future__ import annotations

from opfor.core import Message, Provider, extract_json_object

SYSTEM = (
    "You identify the software product behind a web host from the evidence of a recon "
    "probe, response headers, page title, cookies, and the bodies of version endpoints. "
    "Name the product only when the evidence supports it, never guess from a host name. "
    "When the product is a known open-source or commercial product, give its NVD CPE "
    "vendor and product as a `vendor:product` string, for example grafana:grafana, "
    "gitlab:gitlab, or jenkins:jenkins. Give the version only when the evidence shows it.\n\n"
    "Reply with a single JSON object and nothing else, of the form "
    '{"product": "", "version": "", "cpe": ""}. Leave a field empty when the evidence does '
    "not support it, and return every field empty when the host is a bespoke application or "
    "cannot be identified. Do not invent a product or a version."
)


def identify_service(provider: Provider, model: str, evidence: str) -> dict:
    """Ask the model to name the product, version, and CPE for one host's evidence.

    Returns a dict with `product`, `version`, and `cpe`, each empty when unknown. A model
    call that fails raises, the caller reports that loud, but a reply that identifies
    nothing is a clean empty answer, since not every host is a recognizable product.
    """
    result = provider.complete(
        system=SYSTEM,
        messages=[Message(role="user", content=f"# Host evidence\n\n{evidence}\n")],
        model=model,
        max_tokens=512,
        cache=False,
    )
    obj = extract_json_object(result.text) or {}
    return {
        "product": str(obj.get("product", "")).strip(),
        "version": str(obj.get("version", "")).strip(),
        "cpe": str(obj.get("cpe", "")).strip(),
    }
