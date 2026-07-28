"""Identify the product behind a host from its HTTP evidence, with a model.

This is the seam the CVE scan calls to turn raw signals, headers, titles, and version
endpoints, into a product, a version, and a CPE the vulnerability lookup can query. It is
model-backed so it recognizes a novel or obscure product rather than matching a fixed
table, and it stays a seam so the capability that calls it holds no model and no knowledge.
Identifying nothing is a valid answer, a JSON object with empty fields, not an error. A reply
that carries no JSON object at all is a model failure, not a clean negative, so it raises,
invariant 5.
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
    '{"product": "", "version": "", "cpe": "", "conclusive": true}. Leave a field empty when the '
    "evidence does not support it, and return every field empty when the host is a bespoke "
    "application or cannot be identified. Do not invent a product or a version. Set `conclusive` "
    "to true when the evidence was enough to decide, whether you named a product or judged the "
    "host a bespoke application, and false only when the host exposed too little to judge at all, "
    "such as a page that answered but carried almost no identifying content."
)


def identify_service(provider: Provider, model: str, evidence: str) -> dict:
    """Ask the model to name the product, version, and CPE for one host's evidence.

    Returns a dict with `product`, `version`, and `cpe`, each empty when unknown, and
    `conclusive`, false when the host exposed too little to judge at all so an empty product is
    unknown rather than a confirmed bespoke negative, which the profiler records as a coverage
    gap. A model call that fails raises, the caller reports that loud. A reply that carries no
    JSON object raises too, since that is the model failing the contract, not a host that is
    unrecognizable. A JSON object with empty fields is the clean empty answer, not every host
    is a product.
    """
    result = provider.complete(
        system=SYSTEM,
        messages=[Message(role="user", content=f"# Host evidence\n\n{evidence}\n")],
        model=model,
        max_tokens=512,
        cache=False,
    )
    obj = extract_json_object(result.text)
    if obj is None:
        raise RuntimeError("the identify model reply carried no JSON object")
    return {
        "product": str(obj.get("product", "")).strip(),
        "version": str(obj.get("version", "")).strip(),
        "cpe": str(obj.get("cpe", "")).strip(),
        "conclusive": bool(obj.get("conclusive", True)),
    }
