"""Public data sources for on-chain target discovery, key-light and injectable.

Each function queries one public source and returns its raw, structured answer.
None of them judge anything, they only fetch and shape, so the "attack knowledge
is data, executors only act" line holds: the planner and triage decide what a
result means, these just report it.

Sources cover the two axes we care about, value and risk, plus recency:
- Moralis names which contracts actually hold money (token top-holders, with a
  per-holder USD value and an is-contract flag), so it is the seed; and its first
  transaction of an address is that address's creation, which dates a contract.
- GoPlus returns per-contract risk flags (honeypot, mintable, hidden owner, ...).
- Etherscan (one V2 key, multichain by chainid) says whether the source is
  verified, on which compiler, whether it is a proxy, and its contract name (used
  to spot standard templates).
- DeFiLlama (protocol TVL per chain) is retained as an alternate value seed; the
  active seed is Moralis holders, because DeFiLlama only pins one governance-token
  address per protocol, not the fund-holding contracts.

The HTTP call is a single injected seam (`http_get`) so a test drives the whole
scenario with fixtures and never touches a live endpoint or spends a real key.
The Etherscan key travels only in the request URL to Etherscan (redacted out of
anything we hand back); the Moralis key travels only in a request header. Neither
ever lands in an observation, a fact, or a log.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Callable

from opfor.useragent import pick_ua

# What an HTTP getter returns: the raw response body. Callable[[url, headers], bytes].
HttpGet = Callable[[str, dict | None], bytes]

_TIMEOUT = 30


def http_get(url: str, headers: dict | None = None) -> bytes:
    """Default getter: a plain GET with a browser-ish User-Agent."""
    hdrs = {"User-Agent": pick_ua()}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        return resp.read()


# Per-chain identifiers across the three sources. Adding a chain is a data change
# here, not a code change in the executors.
CHAINS: dict[str, dict] = {
    "bsc": {
        "defillama_label": "Binance",  # the label in a protocol's `chains` array
        "defillama_prefix": "bsc",     # the prefix on a chain-scoped `address`
        "etherscan_chainid": 56,
        "goplus_chainid": 56,
        "moralis_chain": "bsc",        # Moralis chain identifier
        "explorer": "https://bscscan.com/address/",
    },
}


def chain_info(chain: str) -> dict:
    info = CHAINS.get(chain)
    if info is None:
        known = ", ".join(sorted(CHAINS))
        raise ValueError(f"unsupported chain {chain!r}, known: {known}")
    return info


# --- DeFiLlama: where the money is (the seed) ------------------------------


def defillama_protocols(
    get: HttpGet, chain: str, *, min_tvl: float, top_n: int
) -> list[dict]:
    """Protocols with a concrete on-chain contract on `chain`, richest first.

    Only protocols whose `address` is chain-scoped (e.g. `bsc:0x...`) yield a
    usable contract address, so the rest are skipped, we cannot audit a protocol
    we cannot pin to an address. TVL is the chain-specific value from chainTvls,
    not the protocol's cross-chain total, so the ranking reflects money on BSC.
    """
    info = chain_info(chain)
    label = info["defillama_label"]
    prefix = info["defillama_prefix"] + ":"
    raw = json.loads(get("https://api.llama.fi/protocols", None).decode("utf-8", "replace"))
    out: list[dict] = []
    for p in raw:
        address = p.get("address")
        if not isinstance(address, str) or not address.startswith(prefix):
            continue
        addr = address[len(prefix):].strip().lower()
        if not _looks_like_evm_address(addr):
            continue
        chain_tvls = p.get("chainTvls") or {}
        tvl = chain_tvls.get(label)
        if tvl is None and label in (p.get("chains") or []):
            tvl = p.get("tvl")
        if not isinstance(tvl, (int, float)) or tvl < min_tvl:
            continue
        out.append({
            "name": str(p.get("name", "")),
            "slug": str(p.get("slug", "")),
            "address": addr,
            "tvl": float(tvl),
            "category": str(p.get("category", "")),
        })
    out.sort(key=lambda d: d["tvl"], reverse=True)
    return out[:top_n] if top_n and top_n > 0 else out


def _looks_like_evm_address(addr: str) -> bool:
    return (
        addr.startswith("0x")
        and len(addr) == 42
        and all(c in "0123456789abcdef" for c in addr[2:])
    )


# --- Moralis: which contracts hold money, and when they were born ----------

MORALIS_BASE = "https://deep-index.moralis.io/api/v2.2"


def _moralis_headers(api_key: str) -> dict:
    # The key travels only in this header, never in a returned value or a log.
    return {"X-API-Key": api_key, "accept": "application/json"}


def moralis_token_owners(
    get: HttpGet, api_key: str, chain: str, token: str, *, limit: int = 100,
    cursor: str | None = None,
) -> dict:
    """One page of a token's holders, richest first.

    Each holder record carries `owner_address`, `usd_value`, `is_contract`, and
    labels (`owner_address_label`, `entity`) when Moralis knows them. Returns the
    page plus the cursor for the next one; we only fetch, we do not judge.
    """
    info = chain_info(chain)
    query = {"chain": info["moralis_chain"], "order": "DESC", "limit": str(limit)}
    if cursor:
        query["cursor"] = cursor
    url = f"{MORALIS_BASE}/erc20/{token}/owners?" + urllib.parse.urlencode(query)
    body = json.loads(get(url, _moralis_headers(api_key)).decode("utf-8", "replace"))
    return {"result": body.get("result") or [], "cursor": body.get("cursor")}


def moralis_value_contracts(
    get: HttpGet, api_key: str, chain: str, tokens: list[str], *,
    min_usd: float, max_usd: float, max_pages: int,
) -> dict:
    """Contracts holding an in-band USD amount of any token in a basket.

    Pages each token's holder list from the top, keeps holders that are contracts
    (`is_contract`) whose USD value lands in [min_usd, max_usd], and aggregates by
    address so a contract holding several assets sums across them. Paging stops for
    a token once a holder falls below the band (the list is value-sorted) or the
    page cap is hit. A token still above the band at the cap is recorded in
    `truncated`, so the caller can report the coverage was bounded, never silently.
    """
    contracts: dict[str, dict] = {}
    truncated: list[str] = []
    for token in tokens:
        cursor = None
        pages = 0
        last: float | None = None
        while pages < max_pages:
            page = moralis_token_owners(get, api_key, chain, token, cursor=cursor)
            rows = page["result"]
            pages += 1
            if not rows:
                break
            for row in rows:
                usd = _as_float(row.get("usd_value"))
                last = usd
                if not row.get("is_contract"):
                    continue
                if usd is None or not (min_usd <= usd <= max_usd):
                    continue
                addr = str(row.get("owner_address", "")).lower()
                if not _looks_like_evm_address(addr):
                    continue
                entry = contracts.setdefault(
                    addr, {"usd": 0.0, "tokens": {}, "label": None, "entity": None})
                entry["usd"] += usd
                entry["tokens"][token.lower()] = usd
                if row.get("owner_address_label"):
                    entry["label"] = str(row["owner_address_label"])
                if row.get("entity"):
                    entry["entity"] = str(row["entity"])
            cursor = page["cursor"]
            if last is not None and last < min_usd:
                break
            if not cursor:
                break
        if pages >= max_pages and last is not None and last >= min_usd:
            truncated.append(token.lower())
    return {"contracts": contracts, "truncated": truncated}


def moralis_first_seen(get: HttpGet, api_key: str, chain: str, address: str) -> dict:
    """When an address was first active, i.e. its creation.

    A contract's earliest transaction is the transaction that created it, so the
    oldest transaction's block timestamp dates the deployment. Returns the raw
    timestamp and block; the age (and whether that is "fresh") is computed later,
    against a reference date, so this stays a pure fetch.
    """
    info = chain_info(chain)
    query = {"chain": info["moralis_chain"], "order": "ASC", "limit": "1"}
    url = f"{MORALIS_BASE}/{address.lower()}?" + urllib.parse.urlencode(query)
    body = json.loads(get(url, _moralis_headers(api_key)).decode("utf-8", "replace"))
    rows = body.get("result") or []
    first = rows[0] if rows else {}
    return {
        "born_ts": first.get("block_timestamp"),
        "born_block": first.get("block_number"),
    }


def _as_float(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# --- GoPlus: per-contract risk flags (the risk axis) -----------------------

# Flags GoPlus returns as "1"/"0" strings. We normalize the tripped ones into a
# list; we do not weigh them, that is the planner's and triage's call.
GOPLUS_FLAGS = (
    "is_honeypot", "cannot_sell_all", "cannot_buy", "is_mintable",
    "can_take_back_ownership", "hidden_owner", "selfdestruct",
    "external_call", "is_blacklisted", "is_whitelisted", "is_proxy",
    "transfer_pausable", "trading_cooldown", "is_anti_whale",
    "owner_change_balance", "slippage_modifiable", "personal_slippage_modifiable",
)


def goplus_token_security(get: HttpGet, chain: str, address: str) -> dict:
    """Raw GoPlus token-security result for one contract, or {} if not covered.

    GoPlus keys the result map by the lowercased address; an address it has never
    seen (not a token, brand new) simply is not in the map, which is an empty
    result, not an error.
    """
    info = chain_info(chain)
    chain_id = info["goplus_chainid"]
    addr = address.lower()
    url = (
        f"https://api.gopluslabs.io/api/v1/token_security/{chain_id}"
        f"?contract_addresses={urllib.parse.quote(addr)}"
    )
    body = json.loads(get(url, None).decode("utf-8", "replace"))
    result = body.get("result") or {}
    return result.get(addr) or result.get(address) or {}


def tripped_flags(security: dict) -> list[str]:
    """The GoPlus flags that are set. Structuring, not judgment."""
    return sorted(name for name in GOPLUS_FLAGS if str(security.get(name, "")) == "1")


# --- Etherscan V2: verification and compiler metadata ----------------------


def etherscan_source_meta(
    get: HttpGet, api_key: str, chain: str, address: str
) -> dict:
    """Verification/compiler/proxy metadata for one contract via Etherscan V2.

    Returns the normalized fields we care about. The api key is only ever placed
    in the outbound URL to Etherscan; the returned dict carries a `source_url`
    with the key redacted, so nothing downstream can leak it.
    """
    info = chain_info(chain)
    chain_id = info["etherscan_chainid"]
    addr = address.lower()
    query = {
        "chainid": str(chain_id),
        "module": "contract",
        "action": "getsourcecode",
        "address": addr,
        "apikey": api_key,
    }
    url = "https://api.etherscan.io/v2/api?" + urllib.parse.urlencode(query)
    body = json.loads(get(url, None).decode("utf-8", "replace"))
    result = body.get("result")
    entry = result[0] if isinstance(result, list) and result else {}
    source_code = str(entry.get("SourceCode", "") or "")
    return {
        "verified": bool(source_code.strip()),
        "contract_name": str(entry.get("ContractName", "") or ""),
        "compiler_version": str(entry.get("CompilerVersion", "") or ""),
        "is_proxy": str(entry.get("Proxy", "")) == "1",
        "implementation": str(entry.get("Implementation", "") or ""),
        "license": str(entry.get("LicenseType", "") or ""),
        # Redacted so a fact or log never carries the key.
        "source_url": _redact_key(url),
        "api_status": str(body.get("status", "")),
        "api_message": str(body.get("message", "")),
    }


def _redact_key(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    redacted = [(k, "REDACTED" if k == "apikey" else v) for k, v in query]
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(redacted), parts.fragment)
    )
