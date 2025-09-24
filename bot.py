#!/usr/bin/env python3
"""
GalaSwap Python Bot — merged (paper + live) + Tri-leg quote/evaluate
- Scans both directions for a pair (e.g., GWETH <-> GALA/GSILK)
- Uses /v1/tokens to resolve token metadata (and USD refs)
- Uses /v1/FetchAvailableTokenSwaps to find live offers
- Optionally signs + fills with /v1/BatchFillTokenSwap
- Falls back to paper mode automatically if signing env is missing
- Tri-leg path scan: A->B->C->A (depth-aware, scan-only by default)
"""

import os, time, json, math, base64, random, uuid
from dataclasses import dataclass
from decimal import Decimal, getcontext
from typing import Any, Dict, List, Tuple, Optional
from copy import deepcopy
from collections import deque

import requests
from dotenv import load_dotenv

# ---------- env & config ----------
load_dotenv()

API_BASE = os.getenv("API_BASE", "https://api-galaswap.gala.com")

# Pair config
PAIR_A = os.getenv("BASE_TOKEN",  "GWETH").upper()
PAIR_B = os.getenv("QUOTE_TOKEN", "SILK").upper()

# Strategy thresholds
EDGE_PCT        = Decimal(os.getenv("MIN_EDGE_PCT", "0.40"))   # % better than USD reference
LOOP_SECONDS    = float(os.getenv("LOOP_SECONDS", "4"))
MAX_FILLS_TICK  = int(os.getenv("MAX_FILL_PER_TICK", "1"))

# Safety (optional hard min-out in human units; 0 disables)
MIN_WANTED_A2B  = Decimal(os.getenv("MIN_WANTED_A2B", "0"))    # min B for 1 A fill
MIN_WANTED_B2A  = Decimal(os.getenv("MIN_WANTED_B2A", "0"))    # min A for 1 B fill

# Paper-mode sizing (for mock cycles). Only used if live signing is missing.
PAPER_START_BASE = Decimal(os.getenv("START_AMOUNT", "0.01"))   # 0.01 A token
PAPER_MIN_PROFIT = Decimal(os.getenv("MIN_PROFIT_USD", "0.50"))

# Signing (presence of all three flips to LIVE mode for fills)
WALLET_ADDR = os.getenv("X_WALLET_ADDRESS", "").strip()      # e.g., client|xxxxx
PRIV_HEX    = os.getenv("PRIVATE_KEY_HEX", "").strip()       # 0x...
PUB_B64     = os.getenv("PUBLIC_KEY_B64", "").strip()        # base64 public key

LIVE_CAN_FILL   = bool(WALLET_ADDR and PRIV_HEX and PUB_B64)
LIVE_SCAN_ONLY  = os.getenv("LIVE_SCAN_ONLY", "0") == "1"

# Only allow fills if keys are present AND we're not in scan-only mode
CAN_FILL = LIVE_CAN_FILL and (not LIVE_SCAN_ONLY)


# filtering sanity (pair scan)
MIN_NOTIONAL_USD    = Decimal(os.getenv("MIN_NOTIONAL_USD", "5"))   # skip trades smaller than $5
MAX_EDGE_MULTIPLIER = Decimal(os.getenv("MAX_EDGE_MULTIPLIER", "5"))# skip if rate looks >5x better than fair unless it's large

# risk caps
MAX_TOTAL_FILLS   = int(os.getenv("MAX_TOTAL_FILLS", "0"))  # 0 = disabled
MAX_DRAWDOWN_USD  = Decimal(os.getenv("MAX_DRAWDOWN_USD", "0"))  # 0 = disabled

# ---- Tri-leg scan settings (scan-only; no fills here) ----
ENABLE_TRI_SCAN       = os.getenv("ENABLE_TRI_SCAN", "0") == "1"
TRI_BASE_TOKEN        = os.getenv("TRI_BASE_TOKEN", "GALA").upper()
TRI_PATHS_RAW         = os.getenv("TRI_PATHS", "GALA,GUSDC,GWETH,GALA")  # semicolon-separated groups
TRI_BASE_TRADE_SIZE   = Decimal(os.getenv("TRI_BASE_TRADE_SIZE", "100")) # amount in A for evaluation
TRI_MIN_EDGE_PCT      = Decimal(os.getenv("TRI_MIN_EDGE_PCT", "0.20"))   # net edge across whole cycle
TRI_MIN_NOTIONAL_USD  = Decimal(os.getenv("TRI_MIN_NOTIONAL_USD", "10")) # dust floor per leg (taker pays)
TRI_MAX_EDGE_MULT     = Decimal(os.getenv("TRI_MAX_EDGE_MULTIPLIER", "5"))

USED_CACHE = set()
USED_QUEUE = deque()
USED_CACHE_MAX = 200
def remember_used(srid: str):
    if srid in USED_CACHE: return
    USED_CACHE.add(srid); USED_QUEUE.append(srid)
    if len(USED_QUEUE) > USED_CACHE_MAX:
        old = USED_QUEUE.popleft()
        USED_CACHE.discard(old)

# Decimal precision (high precision math)
getcontext().prec = 42

S = requests.Session()
S.headers.update({"Content-Type": "application/json"})

# ---------- helpers ----------
def is_swap_already_used(resp: Dict[str, Any]) -> bool:
    """Detect 409 SWAP_ALREADY_USED from accept_swap response."""
    try:
        if resp.get("status") == 409:
            body = resp.get("response", {})
            # body may be dict or str
            if isinstance(body, dict):
                return str(body.get("error", "")).upper() == "SWAP_ALREADY_USED"
            return "SWAP_ALREADY_USED" in str(body).upper()
    except Exception:
        pass
    return False

def safe_swap_request_id(off: Dict[str, Any]) -> str:
    srid = off.get("swapRequestId", "")
    return "".join(ch for ch in srid if ord(ch) >= 32)

def sanitize_swap_id(srid: str) -> str:
    # Remove embedded NULs or stray control chars that break validation/parsing
    return "".join(ch for ch in srid if ord(ch) >= 32)

def build_expected_from_offer(off: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return the EXACT offered/wanted arrays from the maker offer (raw integer strings).
    Do NOT convert quantities to human units here.
    """
    exp = {
        "offered": deepcopy(off["offered"]),
        "wanted":  deepcopy(off["wanted"]),
    }
    # normalize quantities to strings (they should already be strings)
    for side in ("offered", "wanted"):
        for leg in exp[side]:
            q = leg.get("quantity")
            # enforce string type (no floats)
            leg["quantity"] = str(q)
    return exp

def d(x) -> Decimal:
    return x if isinstance(x, Decimal) else Decimal(str(x))

def try_imports_for_keccak():
    try:
        import sha3  # noqa
        return "sha3"
    except Exception:
        pass
    try:
        from eth_utils import keccak  # noqa
        return "eth_utils"
    except Exception:
        pass
    return None

def keccak256_bytes(data: bytes) -> bytes:
    # Prefer pysha3 if available, otherwise eth_utils.keccak
    which = try_imports_for_keccak()
    if which == "sha3":
        import sha3
        k = sha3.keccak_256(); k.update(data); return k.digest()
    elif which == "eth_utils":
        from eth_utils import keccak
        return keccak(data)
    raise RuntimeError("No keccak backend found. Install eth-hash[pysha3] or eth-utils.")

def canonical(obj: Any) -> str:
    """Stable, compact JSON with keys sorted and signature/trace removed."""
    def strip(o):
        if isinstance(o, dict):
            return {k: strip(v) for k, v in o.items() if k not in ("signature", "trace")}
        if isinstance(o, list):
            return [strip(x) for x in o]
        return o
    clean = strip(obj)
    return json.dumps(clean, separators=(",", ":"), sort_keys=True)

def sign_payload(priv_hex: str, payload_json_min: str) -> str:
    """Return base64 signature (r||s||v) of keccak256(payload) with v in {27,28}."""
    from coincurve import PrivateKey
    pk = PrivateKey.from_hex(priv_hex[2:] if priv_hex.startswith("0x") else priv_hex)
    digest = keccak256_bytes(payload_json_min.encode("utf-8"))
    sig65 = bytearray(pk.sign_recoverable(digest, hasher=None))  # r(32)+s(32)+recId(1: 0/1)
    sig65[64] = (sig65[64] % 2) + 27  # -> 27 (0x1b) or 28 (0x1c)
    return base64.b64encode(bytes(sig65)).decode()

def decode_fill_error(res: dict) -> tuple[int, str]:
    """
    Returns (status_code, canonical_error_key)
    canonical_error_key is UPPER_SNAKE or '' if unknown
    """
    status = int(res.get("status", 0))
    body = res.get("response", {})
    if isinstance(body, dict):
        # common fields from GalaSwap
        for key in ("error", "ErrorKey", "message"):
            v = body.get(key)
            if isinstance(v, str) and v.strip():
                return status, v.strip().upper().replace(" ", "_")
        # nested validation error
        ve = body.get("validationError") or body.get("ValidationError")
        if isinstance(ve, dict):
            name = ve.get("name")
            if name:
                return status, str(name).upper()
    # string body
    if isinstance(body, str) and body.strip():
        return status, body.strip().upper().replace(" ", "_")
    return status, ""

def is_used_error(res: dict) -> bool:
    status, key = decode_fill_error(res)
    return status == 409 and key == "SWAP_ALREADY_USED"


# ---------- token + pool discovery ----------
def get_tokens(symbols: List[str]) -> Dict[str, Any]:
    url = f"{API_BASE}/v1/tokens"
    params = {"symbols": ",".join(symbols)}
    r = S.get(url, params=params, timeout=20)
    r.raise_for_status()
    js = r.json()
    return {t["symbol"]: t for t in js.get("tokens", [])}

def resolve_symbol(sym: str) -> Tuple[str, Dict[str, Any]]:
    """
    Try sym, then 'G'+sym (e.g., SILK -> GSILK). Returns (resolved_symbol, token_meta).
    Raises if neither is found.
    """
    candidates = [sym, f"G{sym}" if not sym.startswith("G") else sym]
    toks = get_tokens(candidates)
    for c in candidates:
        if c in toks:
            return c, toks[c]
    raise RuntimeError(f"Token {sym} not found (tried {candidates}).")

def token_class(meta: Dict[str, Any]) -> Dict[str, str]:
    return {
        "collection":   meta["collection"],
        "category":     meta["category"],
        "type":         meta["type"],
        "additionalKey": meta["additionalKey"]
    }

def token_decimals(meta: Dict[str, Any], default: int = 18) -> int:
    return int(meta.get("decimals", default))

def usd_ref(meta: Dict[str, Any]) -> Decimal:
    px = meta.get("currentPrices", {}).get("usd")
    try:
        return d(px) if px is not None else d(0)
    except Exception:
        return d(0)

# ---------- swap discovery ----------
def fetch_swaps(offered_cls: Dict[str, str], wanted_cls: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Read maker offers (opposite-side):
    - If you (taker) want X->Y, fetch offered=Y, wanted=X
    """
    url = f"{API_BASE}/v1/FetchAvailableTokenSwaps"
    body = {"offeredTokenClass": offered_cls, "wantedTokenClass": wanted_cls}
    r = S.post(url, data=json.dumps(body), timeout=30)
    r.raise_for_status()
    data = r.json()
    if isinstance(data, dict) and "results" in data:
        return data["results"]
    if isinstance(data, list):
        return data
    return []

def quantity_to_decimal(qty_str: str, decimals: int) -> Decimal:
    q_raw = Decimal(qty_str)
    scale = d(10) ** d(decimals)
    return q_raw / scale

def implied_rate_wanted_per_offered(swap: Dict[str, Any], dec_offered: int, dec_wanted: int) -> Decimal:
    o_qty = d(swap["offered"][0]["quantity"])
    w_qty = d(swap["wanted"][0]["quantity"])
    if o_qty <= 0:
        return d(0)
    o_human = o_qty / (d(10) ** dec_offered)
    w_human = w_qty / (d(10) ** dec_wanted)
    if o_human == 0:
        return d(0)
    return (w_human / o_human)

def better_than_ref(rate: Decimal, ref_rate: Decimal, edge_pct: Decimal) -> bool:
    if ref_rate <= 0:
        return False
    return (rate / ref_rate - 1) * 100 >= edge_pct

# ---------- filling ----------
def accept_swap(swap: Dict[str, Any], expected: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    url = f"{API_BASE}/v1/BatchFillTokenSwap"

    # Use the original swapRequestId exactly (but sanitized)
    srid = sanitize_swap_id(swap["swapRequestId"])

    # If caller didn’t provide an expected block, build it from the maker offer (raw units)
    safe_expected = expected if expected is not None else build_expected_from_offer(swap)

    body = {
        "swapDtos": [{
            "swapRequestId": srid,
            "uses": "1",
            "expectedTokenSwap": safe_expected
        }],
        # MUST start with this prefix per API schema
        "uniqueKey": f"galaswap-operation-{os.urandom(8).hex()}",
        "signerPublicKey": PUB_B64
    }

    payload_min = canonical(body)
    sig_b64 = sign_payload(PRIV_HEX, payload_min)
    body["signature"] = sig_b64

    headers = {"X-Wallet-Address": WALLET_ADDR, "Content-Type": "application/json"}

    r = S.post(url, data=json.dumps(body), headers=headers, timeout=30)
    try:
        resp = r.json()
    except Exception:
        resp = {"raw": r.text}
    return {"status": r.status_code, "response": resp}

# ---------- paper mode (no signing) ----------
@dataclass
class Quote:
    out_amount: Decimal
    price: Decimal
    route: str

FEE_BPS_PER_SWAP = Decimal(os.getenv("FEE_BPS_PER_SWAP", "30"))   # 0.30%
SLIPPAGE_BPS     = Decimal(os.getenv("SLIPPAGE_BPS", "15"))       # 0.15%

def bps(x: Decimal) -> Decimal:
    return x / d(10_000)

def mock_get_price_in(pair_in: str, pair_out: str, amount_in: Decimal) -> Quote:
    base = {
        "GWETH->SILK": d(2500),
        "GSILK->GWETH": d(1) / d(2500),
        "GWETH->GSILK": d(2500),
        "SILK->GWETH": d(1) / d(2500),
    }
    key = f"{pair_in}->{pair_out}"
    px = base.get(key, d(1))
    px *= (d(1) + d(random.uniform(-0.0008, 0.0008)))
    gross = amount_in * px
    net = gross * (d(1) - bps(FEE_BPS_PER_SWAP + SLIPPAGE_BPS))
    return Quote(out_amount=net, price=px, route=key)

def paper_cycle_once(amount_base: Decimal, symA: str, symB: str) -> Dict[str, Any]:
    q1 = mock_get_price_in(symA, symB, amount_base)
    q2 = mock_get_price_in(symB, symA, q1.out_amount)
    pnl_base = q2.out_amount - amount_base
    usd_px = d(2500)  # rough ref for demo
    pnl_usd = pnl_base * usd_px
    return {"leg1": q1, "leg2": q2, "start_base": amount_base, "end_base": q2.out_amount,
            "pnl_base": pnl_base, "pnl_usd": pnl_usd}

# ---------- math helpers used by live scan ----------
def human_qty(qty_str: str, decimals: int) -> Decimal:
    """Convert raw quantity string to human units using token decimals."""
    return d(qty_str) / (d(10) ** decimals)

def usd_notional_from_wanted(wanted_arr, wanted_decimals: int, ref_wanted_usd: Decimal) -> Decimal:
    """
    USD value of what YOU (the taker) will pay on this leg.
    The taker always pays the token the maker *wants* (i.e., `wanted` side).
    """
    wanted_qty_human = human_qty(wanted_arr[0]["quantity"], wanted_decimals)
    return wanted_qty_human * ref_wanted_usd

def rate_offered_per_wanted(swap: Dict[str, Any], dec_offered: int, dec_wanted: int) -> Decimal:
    """
    Returns (offered / wanted) in human units.
    - For A->B leg (maker offers B, wants A): this yields B per 1 A
    - For B->A leg (maker offers A, wants B): this yields A per 1 B
    """
    offered_h = human_qty(swap["offered"][0]["quantity"], dec_offered)
    wanted_h  = human_qty(swap["wanted"][0]["quantity"],  dec_wanted)
    return offered_h / wanted_h if wanted_h > 0 else d(0)

# ---------- depth-aware leg fill (for tri evaluation) ----------
def best_fill_for_amount(
    offers: List[Dict[str, Any]],
    amount_in_human: Decimal,
    dec_in: int,   # decimals of the token you PAY (maker wants)
    dec_out: int,  # decimals of the token you RECEIVE (maker offers)
    ref_rate: Decimal,
    min_notional_usd: Decimal,
    ref_in_usd: Decimal,
    edge_mult_limit: Decimal,
) -> Tuple[bool, Decimal, Decimal, List[Tuple[str, Decimal, Decimal]]]:
    """
    Consume multiple offers until 'amount_in_human' is satisfied.
    Returns: (ok, out_amount_human, effective_rate, fills_detail)
    - effective_rate = total_out / total_in  (same orientation as ref_rate)
    """
    offers_sorted = sorted(
        offers, key=lambda s: rate_offered_per_wanted(s, dec_out, dec_in), reverse=True
    )

    remaining = amount_in_human
    total_in = d(0)
    total_out = d(0)
    fills_detail = []

    for off in offers_sorted:
        rate = rate_offered_per_wanted(off, dec_out, dec_in)  # out per 1 in
        wanted_h = human_qty(off["wanted"][0]["quantity"], dec_in)
        offered_h = human_qty(off["offered"][0]["quantity"], dec_out)

        if ref_rate > 0:
            edge_mult = rate / ref_rate
            offer_notional_usd = wanted_h * ref_in_usd
            if edge_mult > edge_mult_limit and offer_notional_usd < (min_notional_usd * 10):
                continue

        if wanted_h <= 0 or offered_h <= 0:
            continue

        take_in = wanted_h if wanted_h <= remaining else remaining
        take_out = offered_h * (take_in / wanted_h)

        total_in += take_in
        total_out += take_out
        fills_detail.append((off.get("swapRequestId", "")[:10], take_in, take_out))

        remaining -= take_in
        if remaining <= 0:
            break

    if total_in <= 0:
        return False, d(0), d(0), fills_detail

    if total_in * ref_in_usd < min_notional_usd:
        return False, d(0), d(0), fills_detail

    effective_rate = total_out / total_in
    return True, total_out, effective_rate, fills_detail

# ---------- tri-leg quote & evaluate (scan-only) ----------
def tri_quote_and_evaluate(
    path_symbols: Tuple[str, str, str, str],
    trade_size_A: Decimal,
) -> Dict[str, Any]:
    """
    Evaluate A->B->C->A, depth-aware, using offer books (opposite-side maker quotes).
    Returns a dict with pass/fail, per-leg details, and overall edge/net.
    """
    A_sym, B_sym, C_sym, A2_sym = path_symbols
    assert A_sym == A2_sym, "Path must start and end with the same token"

    # Resolve tokens + refs + decimals
    resA, metaA = resolve_symbol(A_sym)
    resB, metaB = resolve_symbol(B_sym)
    resC, metaC = resolve_symbol(C_sym)
    decA, decB, decC = token_decimals(metaA), token_decimals(metaB), token_decimals(metaC)
    refA, refB, refC = usd_ref(metaA), usd_ref(metaB), usd_ref(metaC)

    clsA, clsB, clsC = token_class(metaA), token_class(metaB), token_class(metaC)

    # Reference cross-rates
    ref_A2B = (refA / refB) if (refA > 0 and refB > 0) else d(0)  # B per A
    ref_B2C = (refB / refC) if (refB > 0 and refC > 0) else d(0)  # C per B
    ref_C2A = (refC / refA) if (refC > 0 and refA > 0) else d(0)  # A per C

    # leg 1: A->B (maker OFFERS B, WANTS A)
    offers_A2B = fetch_swaps(offered_cls=clsB, wanted_cls=clsA)
    ok1, outB, rate1, fills1 = best_fill_for_amount(
        offers_A2B, trade_size_A, decA, decB, ref_A2B, TRI_MIN_NOTIONAL_USD, refA, TRI_MAX_EDGE_MULT
    )
    if not ok1:
        return {"ok": False, "reason": "insufficient A->B depth or below min notional"}

    # leg 2: B->C (maker OFFERS C, WANTS B)
    offers_B2C = fetch_swaps(offered_cls=clsC, wanted_cls=clsB)
    ok2, outC, rate2, fills2 = best_fill_for_amount(
        offers_B2C, outB, decB, decC, ref_B2C, TRI_MIN_NOTIONAL_USD, refB, TRI_MAX_EDGE_MULT
    )
    if not ok2:
        return {"ok": False, "reason": "insufficient B->C depth or below min notional"}

    # leg 3: C->A (maker OFFERS A, WANTS C)
    offers_C2A = fetch_swaps(offered_cls=clsA, wanted_cls=clsC)
    ok3, outA, rate3, fills3 = best_fill_for_amount(
        offers_C2A, outC, decC, decA, ref_C2A, TRI_MIN_NOTIONAL_USD, refC, TRI_MAX_EDGE_MULT
    )
    if not ok3:
        return {"ok": False, "reason": "insufficient C->A depth or below min notional"}

    # Net & edge
    net_A = outA - trade_size_A
    ref_cycle_mult = ref_A2B * ref_B2C * ref_C2A if (ref_A2B and ref_B2C and ref_C2A) else d(1)
    eff_cycle_mult = rate1 * rate2 * rate3
    edge_pct_total = ((eff_cycle_mult / (ref_cycle_mult if ref_cycle_mult > 0 else d(1))) - 1) * 100

    return {
        "ok": edge_pct_total >= TRI_MIN_EDGE_PCT,
        "edge_pct_total": edge_pct_total,
        "net_A": net_A,
        "legs": [
            {"leg": "A->B", "rate": rate1, "ref": ref_A2B, "fills": fills1, "in": trade_size_A, "out": outB},
            {"leg": "B->C", "rate": rate2, "ref": ref_B2C, "fills": fills2, "in": outB, "out": outC},
            {"leg": "C->A", "rate": rate3, "ref": ref_C2A, "fills": fills3, "in": outC, "out": outA},
        ],
        "path": (resA, resB, resC, resA),
    }

# ---------- main loop (live scan with pair + optional tri scan) ----------
def run_live():
    # risk counters (optional caps)
    total_fills = 0
    cum_pnl_usd = d(0)

    # Resolve tokens (e.g., SILK -> GSILK if needed)
    symA, metaA = resolve_symbol(PAIR_A)
    symB, metaB = resolve_symbol(PAIR_B)
    decA = token_decimals(metaA, 18)
    decB = token_decimals(metaB, 18)
    refA = usd_ref(metaA)  # USD per 1 A
    refB = usd_ref(metaB)  # USD per 1 B

    print(f"[live] scanning {symA} <-> {symB} | refUSD {symA}={refA} {symB}={refB} | edge>={EDGE_PCT}%")
    clsA, clsB = token_class(metaA), token_class(metaB)

    # Parse tri paths (if enabled)
    tri_paths: List[Tuple[str,str,str,str]] = []
    if ENABLE_TRI_SCAN:
        for blk in TRI_PATHS_RAW.split(";"):
            parts = [p.strip().upper() for p in blk.split(",") if p.strip()]
            if len(parts) == 4 and parts[0] == parts[3]:
                tri_paths.append((parts[0], parts[1], parts[2], parts[3]))
            else:
                print(f"[tri] skipped invalid path spec: {blk}")

    while True:
        # hard cap on fills
        if MAX_TOTAL_FILLS > 0 and total_fills >= MAX_TOTAL_FILLS:
            print(f"[risk cap] reached MAX_TOTAL_FILLS={MAX_TOTAL_FILLS}, stopping bot.")
            break

        try:
            # Fetch opposite-side offers for pair scan
            offers_A2B = fetch_swaps(offered_cls=clsB, wanted_cls=clsA)  # you pay A, receive B
            offers_B2A = fetch_swaps(offered_cls=clsA, wanted_cls=clsB)  # you pay B, receive A
            a2b_ids = {o.get("swapRequestId","") for o in offers_A2B}
            b2a_ids = {o.get("swapRequestId","") for o in offers_B2A}
            print(f"[pair] A->B offers={len(offers_A2B)} (unique SRIDs={len(a2b_ids)}) | "
                f"B->A offers={len(offers_B2A)} (unique SRIDs={len(b2a_ids)})")


            # Reference cross-rates
            ref_rate_A2B = (refA / refB) if (refA > 0 and refB > 0) else d(0)  # B per 1 A
            ref_rate_B2A = (refB / refA) if (refA > 0 and refB > 0) else d(0)  # A per 1 B

            fills = 0
            attempted_srids = set()
            used_count_A2B = 0
            used_count_B2A = 0
            MAX_USED_BEFORE_REFRESH = 5  # tweakable



            # ---------- A -> B loop (pay A, receive B) ----------
            seen = skipped_dust = skipped_cartoon = kept = 0
            for off in sorted(offers_A2B,
                              key=lambda s: rate_offered_per_wanted(s, decB, decA),
                              reverse=True):
                seen += 1

                rate = rate_offered_per_wanted(off, decB, decA) # B per 1 A
                edge_ok = better_than_ref(rate, ref_rate_A2B, EDGE_PCT)
                min_ok  = (rate >= MIN_WANTED_A2B) if MIN_WANTED_A2B > 0 else True
                notional_usd = usd_notional_from_wanted(off["wanted"], decA, refA)

                if notional_usd < MIN_NOTIONAL_USD:
                    skipped_dust += 1; continue
                if ref_rate_A2B > 0:
                    edge_mult = rate / ref_rate_A2B
                    if edge_mult > MAX_EDGE_MULTIPLIER and notional_usd < (MIN_NOTIONAL_USD * 10):
                        skipped_cartoon += 1; continue
                
                srid = off.get("swapRequestId", "")
                tail = srid[-8:] if len(srid) > 12 else srid
                print(f"[A->B] offer {tail} rate={rate:.10f} ref={ref_rate_A2B:.10f} ...")


                if edge_ok and min_ok and CAN_FILL and fills < MAX_FILLS_TICK:
                    kept += 1
                    srid = safe_swap_request_id(off)
                    if srid in USED_CACHE or srid in attempted_srids:
                        # already tried this one in this tick, skip
                        continue
                    attempted_srids.add(srid)
                    remember_used(srid)
                    # Build expected from the offer (raw units) or let accept_swap handle it
                    res = accept_swap(off)
                    status, err = decode_fill_error(res)

                    if status == 200:
                        print("FILLED A->B:", res["status"], res["response"])
                        fills += 1
                        total_fills += 1

                        edge_pct = float((rate / ref_rate_A2B - 1) * 100) if ref_rate_A2B > 0 else 0.0
                        approx_pnl_usd = edge_pct / 100.0 * float(notional_usd)
                        cum_pnl_usd += d(approx_pnl_usd)

                        if MAX_DRAWDOWN_USD > 0 and cum_pnl_usd < -MAX_DRAWDOWN_USD:
                            print(f"[risk cap] hit max drawdown {MAX_DRAWDOWN_USD} USD, stopping bot.")
                            return

                        if fills >= MAX_FILLS_TICK:
                            break
                    elif is_swap_already_used(res):
                        print("[info] A->B swap already used, trying next best…")
                        print("[debug] fill error details:", res)
                        used_count_A2B += 1
                        if used_count_A2B >= MAX_USED_BEFORE_REFRESH:
                            print("[info] A->B too many used in a row — refetching offers…")
                            offers_A2B = fetch_swaps(offered_cls=clsB, wanted_cls=clsA)
                            used_count_A2B = 0
                        continue
                    else:
                        print("FILL ERROR A->B:", res)
                        # depending on your preference, either continue to try next, or break on fatal
                        continue


            print(f"[A->B] offers seen={seen} kept={kept} dust={skipped_dust} cartoon={skipped_cartoon}")

            # ---------- B -> A loop (pay B, receive A) ----------
            if fills < MAX_FILLS_TICK:
                seen = skipped_dust = skipped_cartoon = kept = 0
                for off in sorted(offers_B2A,
                                  key=lambda s: rate_offered_per_wanted(s, decA, decB),
                                  reverse=True):
                    seen += 1

                    rate = rate_offered_per_wanted(off, decA, decB) # A per 1 B
                    edge_ok = better_than_ref(rate, ref_rate_B2A, EDGE_PCT)
                    min_ok  = (rate >= MIN_WANTED_B2A) if MIN_WANTED_B2A > 0 else True
                    notional_usd = usd_notional_from_wanted(off["wanted"], decB, refB)

                    if notional_usd < MIN_NOTIONAL_USD:
                        skipped_dust += 1; continue
                    if ref_rate_B2A > 0:
                        edge_mult = rate / ref_rate_B2A
                        if edge_mult > MAX_EDGE_MULTIPLIER and notional_usd < (MIN_NOTIONAL_USD * 10):
                            skipped_cartoon += 1; continue

                    srid = off.get("swapRequestId", "")
                    tail = srid[-8:] if len(srid) > 12 else srid
                    print(f"[B->A] offer {tail} rate={rate:.10f} ref={ref_rate_B2A:.10f} ...")


                    if edge_ok and min_ok and CAN_FILL and fills < MAX_FILLS_TICK:
                        kept += 1
                        srid = safe_swap_request_id(off)
                        if srid in USED_CACHE or srid in attempted_srids:
                            continue
                        attempted_srids.add(srid)
                        remember_used(srid)

                        res = accept_swap(off)

                        if res["status"] == 200:
                            print("FILLED B->A:", res["status"], res["response"])
                            fills += 1
                            total_fills += 1

                            edge_pct = float((rate / ref_rate_B2A - 1) * 100) if ref_rate_B2A > 0 else 0.0
                            approx_pnl_usd = edge_pct / 100.0 * float(notional_usd)
                            cum_pnl_usd += d(approx_pnl_usd)

                            if MAX_DRAWDOWN_USD > 0 and cum_pnl_usd < -MAX_DRAWDOWN_USD:
                                print(f"[risk cap] hit max drawdown {MAX_DRAWDOWN_USD} USD, stopping bot.")
                                return

                            if fills >= MAX_FILLS_TICK:
                                break

                        elif is_swap_already_used(res):
                            print("[info] B->A swap already used, trying next best…")
                            print("[debug] fill error details:", res)
                            used_count_B2A += 1
                            if used_count_B2A >= MAX_USED_BEFORE_REFRESH:
                                print("[info] B->A too many used in a row — refetching offers…")
                                offers_B2A = fetch_swaps(offered_cls=clsA, wanted_cls=clsB)
                                used_count_B2A = 0
                            continue
                        else:
                            print("FILL ERROR B->A:", res)
                            continue


                print(f"[B->A] offers seen={seen} kept={kept} dust={skipped_dust} cartoon={skipped_cartoon}")

            # ---------- Tri-leg scan (quote & evaluate) ----------
            if ENABLE_TRI_SCAN and tri_paths:
                for (A,B,C,_) in tri_paths:
                    res = tri_quote_and_evaluate((A,B,C,A), TRI_BASE_TRADE_SIZE)
                    if not res.get("ok"):
                        reason = res.get("reason") or f"edge<{TRI_MIN_EDGE_PCT}%"
                        print(f"[tri] {A}->{B}->{C}->{A} : NOPE | reason={reason}")
                        continue

                    edge = res["edge_pct_total"]
                    netA = res["net_A"]
                    legs = res["legs"]
                    print(f"[tri] {A}->{B}->{C}->{A} : OK | edge={edge:.3f}% | net {netA:.6f} {A} "
                          f"| leg rates: "
                          f"A->B {legs[0]['rate']:.6f}/{legs[0]['ref']:.6f}, "
                          f"B->C {legs[1]['rate']:.6f}/{legs[1]['ref']:.6f}, "
                          f"C->A {legs[2]['rate']:.6f}/{legs[2]['ref']:.6f}")

                    # Execution stub: if you later enable fills, do each leg with strict amountOutMinimum
                    # and your existing risk caps.

        except requests.HTTPError as e:
            msg = getattr(e.response, "text", str(e))
            print("[HTTP error]", msg)
        except Exception as e:
            print("[loop error]", repr(e))

        time.sleep(LOOP_SECONDS)

def run_paper():
    # Paper mode always uses your chosen symbols verbatim
    symA = PAIR_A
    symB = PAIR_B
    amt  = PAPER_START_BASE
    print(f"[paper] {symA}/{symB} start={amt} loop={LOOP_SECONDS}s fee_bps={FEE_BPS_PER_SWAP}+{SLIPPAGE_BPS} min_profit_usd={PAPER_MIN_PROFIT}")
    while True:
        r = paper_cycle_once(amt, symA, symB)
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}] {r['leg1'].route} -> {r['leg2'].route} | "
              f"start={r['start_base']:.6f} end={r['end_base']:.6f} "
              f"pnl_base={r['pnl_base']:.6f} pnl_usd={r['pnl_usd']:.2f}")
        if r["pnl_usd"] >= PAPER_MIN_PROFIT:
            print(">> PAPER TRADE: would execute both swaps now.")
        time.sleep(LOOP_SECONDS)

def main():
    if LIVE_SCAN_ONLY:
        print(f"Mode: LIVE_SCAN_ONLY | Pair: {PAIR_A}<->{PAIR_B} | API: {API_BASE}")
        run_live()  # scan + tri-scan (if enabled)
        return
    mode = "LIVE" if LIVE_CAN_FILL else "PAPER"
    print(f"Mode: {mode} | Pair: {PAIR_A}<->{PAIR_B} | API: {API_BASE}")
    if LIVE_CAN_FILL:
        run_live()
    else:
        run_paper()

if __name__ == "__main__":
    main()
