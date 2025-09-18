#!/usr/bin/env python3
"""
GalaSwap Python Bot — merged (paper + live)
- Scans both directions for a pair (e.g., GWETH <-> SILK/GSILK)
- Uses /v1/tokens to resolve token metadata (and USD refs)
- Uses /v1/FetchAvailableTokenSwaps to find live offers
- Optionally signs + fills with /v1/BatchFillTokenSwap
- Falls back to paper mode automatically if signing env is missing

Setup:
  pip install python-dotenv requests coincurve eth-utils eth-hash[pysha3]
  python bot.py   # after creating .env (see sample below)

IMPORTANT:
- Start with small amounts.
- Add your PRIVATE_KEY + X_WALLET_ADDRESS only when ready for live fills.
- Tokens on GalaChain are wrapped with a leading "G" (e.g., GWETH, GUSDC, GSILK).
  This bot will try the symbol and its "G" prefix automatically.
"""

import os, time, json, math, base64, random
from dataclasses import dataclass
from decimal import Decimal, getcontext
from typing import Any, Dict, List, Tuple, Optional

import requests
from dotenv import load_dotenv

# ---------- env & config ----------
load_dotenv()

API_BASE = os.getenv("API_BASE", "https://api-galaswap.gala.com")

# Pair config: tuned for GWETH <-> SILK (auto-resolves GSILK if needed)
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

LIVE_CAN_FILL = bool(WALLET_ADDR and PRIV_HEX and PUB_B64)
LIVE_SCAN_ONLY = os.getenv("LIVE_SCAN_ONLY", "0") == "1"

# risk caps
MAX_TOTAL_FILLS   = int(os.getenv("MAX_TOTAL_FILLS", "0"))  # 0 = disabled
MAX_DRAWDOWN_USD  = Decimal(os.getenv("MAX_DRAWDOWN_USD", "0"))  # 0 = disabled



# Decimal precision (high precision math)
getcontext().prec = 42

S = requests.Session()
S.headers.update({"Content-Type": "application/json"})

# ---------- helpers ----------
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
    """Return base64 signature (r||s||v) of keccak256(payload)."""
    from coincurve import PrivateKey
    pk = PrivateKey.from_hex(priv_hex[2:] if priv_hex.startswith("0x") else priv_hex)
    digest = keccak256_bytes(payload_json_min.encode("utf-8"))
    sig65 = pk.sign_recoverable(digest, hasher=None)
    return base64.b64encode(sig65).decode()

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
    """
    Convert on-chain quantity string (integer-like) to human decimal using token decimals.
    If qty is already a floaty string, we still handle it robustly by quantizing.
    """
    # normalize to integer Decimal if possible
    q_raw = Decimal(qty_str)
    scale = d(10) ** d(decimals)
    return q_raw / scale

def implied_rate_wanted_per_offered(swap: Dict[str, Any], dec_offered: int, dec_wanted: int) -> Decimal:
    """
    Returns how many WANTED you receive per 1 OFFERED (both in human units).
    Assumes single-asset both sides (standard spot offer).
    """
    o_qty = d(swap["offered"][0]["quantity"])
    w_qty = d(swap["wanted"][0]["quantity"])
    if o_qty <= 0:
        return d(0)
    # Convert both to human units:
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
def accept_swap(swap: Dict[str, Any], expected: Dict[str, Any]) -> Dict[str, Any]:
    url = f"{API_BASE}/v1/BatchFillTokenSwap"
    body = {
        "swapDtos": [{
            "swapRequestId": swap["swapRequestId"],
            "uses": "1",
            "expectedTokenSwap": expected
        }],
        "uniqueKey": f"bot-{int(time.time()*1000)}",
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
    # tiny random drift
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
# ---------- main loop ----------
def run_live():
    total_fills = 0
    cum_pnl_usd = d(0)   # running estimate of PnL in USD

    # Resolve tokens (SILK -> GSILK if needed)
    symA, metaA = resolve_symbol(PAIR_A)
    symB, metaB = resolve_symbol(PAIR_B)
    decA = token_decimals(metaA, 18)
    decB = token_decimals(metaB, 18)
    refA = usd_ref(metaA)
    refB = usd_ref(metaB)

    print(f"[live] scanning {symA} <-> {symB} | refUSD {symA}={refA} {symB}={refB} | edge>={EDGE_PCT}%")
    clsA, clsB = token_class(metaA), token_class(metaB)

    while True:
        if MAX_TOTAL_FILLS > 0 and total_fills >= MAX_TOTAL_FILLS:
            print(f"[risk cap] reached MAX_TOTAL_FILLS={MAX_TOTAL_FILLS}, stopping bot.")
            break
        fills = 0
        try:
            offers_A2B = fetch_swaps(clsA, clsB)
            offers_B2A = fetch_swaps(clsB, clsA)

            # Reference cross rates from USD refs
            ref_rate_A2B = (refA / refB) if refA > 0 and refB > 0 else d(0)  # SILK per 1 GWETH
            ref_rate_B2A = (refB / refA) if refA > 0 and refB > 0 else d(0)  # GWETH per 1 SILK

            # A -> B
            for off in sorted(offers_A2B, key=lambda s: implied_rate_wanted_per_offered(s, decA, decB), reverse=True):
                rate = implied_rate_wanted_per_offered(off, decA, decB)
                edge_ok = better_than_ref(rate, ref_rate_A2B, EDGE_PCT)
                if MIN_WANTED_A2B > 0:
                    # expected wanted if we consume 1 unit offered:
                    min_ok = rate >= MIN_WANTED_A2B
                else:
                    min_ok = True
                print(f"[A->B] offer {off.get('swapRequestId','')[:10]}… rate={rate:.10f} ref={ref_rate_A2B:.10f} edge_ok={edge_ok} min_ok={min_ok}")
                if edge_ok and min_ok and LIVE_CAN_FILL and fills < MAX_FILLS_TICK:
                    expected = {"offered": off["offered"], "wanted": off["wanted"]}
                    res = accept_swap(off, expected)
                    print("FILLED A->B:", res["status"], res["response"])
                    fills += 1
                    total_fills += 1

                    # estimate pnl (rough: edge × notional in USD)
                    edge_pct = (rate / ref_rate_A2B - 1) * 100
                    approx_pnl_usd = float(edge_pct/100) * float(refA)  # using 1 A token as notional
                    cum_pnl_usd += d(approx_pnl_usd)

                    if MAX_DRAWDOWN_USD > 0 and cum_pnl_usd < -MAX_DRAWDOWN_USD:
                        print(f"[risk cap] hit max drawdown {MAX_DRAWDOWN_USD} USD, stopping bot.")
                        return

                    if fills >= MAX_FILLS_TICK:
                        break

            # B -> A (if room to fill)
            if fills < MAX_FILLS_TICK:
                for off in sorted(offers_B2A, key=lambda s: implied_rate_wanted_per_offered(s, decB, decA), reverse=True):
                    rate = implied_rate_wanted_per_offered(off, decB, decA)
                    edge_ok = better_than_ref(rate, ref_rate_B2A, EDGE_PCT)
                    if MIN_WANTED_B2A > 0:
                        min_ok = rate >= MIN_WANTED_B2A
                    else:
                        min_ok = True
                    print(f"[B->A] offer {off.get('swapRequestId','')[:10]}… rate={rate:.10f} ref={ref_rate_B2A:.10f} edge_ok={edge_ok} min_ok={min_ok}")
                    if edge_ok and min_ok and LIVE_CAN_FILL and fills < MAX_FILLS_TICK:
                        expected = {"offered": off["offered"], "wanted": off["wanted"]}
                        res = accept_swap(off, expected)
                        print("FILLED B->A:", res["status"], res["response"])
                        fills += 1
                        total_fills += 1

                        # estimate pnl (rough: edge × notional in USD)
                        edge_pct = (rate / ref_rate_A2B - 1) * 100
                        approx_pnl_usd = float(edge_pct/100) * float(refA)  # using 1 A token as notional
                        cum_pnl_usd += d(approx_pnl_usd)

                        if MAX_DRAWDOWN_USD > 0 and cum_pnl_usd < -MAX_DRAWDOWN_USD:
                            print(f"[risk cap] hit max drawdown {MAX_DRAWDOWN_USD} USD, stopping bot.")
                            return

                        if fills >= MAX_FILLS_TICK:
                            break

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
        run_live()  # it will scan and print offers
        return
    mode = "LIVE" if LIVE_CAN_FILL else "PAPER"
    print(f"Mode: {mode} | Pair: {PAIR_A}<->{PAIR_B} | API: {API_BASE}")
    if LIVE_CAN_FILL:
        run_live()
    else:
        run_paper()

if __name__ == "__main__":
    main()
