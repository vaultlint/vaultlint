#!/usr/bin/env python3
"""Census of upgradeable programs on Solana mainnet.

Answers two questions across two populations: who can replace a program's code,
and how often the code is actually replaced. Deliberately dependency-free — base58,
ed25519 point decompression and PDA derivation are all done here so the script runs
against a bare Python 3 and can be re-run unchanged in a later quarter.

Usage, in order:

    ./mainnet-census.py population          # all Program accounts -> population.json
    ./mainnet-census.py active              # programs invoked in recent blocks -> active.json
    ./mainnet-census.py headers all 2000    # ProgramData headers for a random sample
    ./mainnet-census.py headers active      # ProgramData headers for the invoked set
    ./mainnet-census.py report              # calibrate, classify, cross-tabulate
    ./mainnet-census.py churn 60            # upgrade history of the busiest programs

Every step writes to --out (default ./census-data) so later steps can re-read it.
"""

import argparse
import base64
import hashlib
import json
import os
import random
import sys
import time
import urllib.request
from collections import Counter

LOADER = "BPFLoaderUpgradeab1e11111111111111111111111"
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# ed25519 field, used only to decide whether an address is a valid curve point.
P = 2**255 - 19
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def b58_decode(s):
    n = 0
    for c in s:
        n = n * 58 + ALPHABET.index(c)
    return n.to_bytes(32, "big")


def b58_encode(b):
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = ALPHABET[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + out


def on_curve(b):
    """True for an ordinary ed25519 public key, False for a program-derived address.

    A PDA is by construction a 32-byte string that is *not* a curve point — that is
    what makes it unsignable by a keypair. So this distinguishes an address a private
    key can sign for from one only a program can authorise.
    """
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= P:
        return False
    yy = y * y % P
    u, v = (yy - 1) % P, (D * yy + 1) % P
    x = u * pow(v, 3, P) % P * pow(u * pow(v, 7, P) % P, (P - 5) // 8, P) % P
    if (v * x * x - u) % P == 0:
        pass
    elif (v * x * x + u) % P == 0:
        x = x * SQRT_M1 % P
    else:
        return False
    return not (x == 0 and sign)


def programdata_address(program_id):
    """The ProgramData PDA holding the authority and the ELF for `program_id`."""
    seed = b58_decode(program_id)
    loader = b58_decode(LOADER)
    for bump in range(255, -1, -1):
        h = hashlib.sha256(seed + bytes([bump]) + loader + b"ProgramDerivedAddress").digest()
        if not on_curve(h):
            return b58_encode(h)
    raise ValueError("no off-curve bump")


class Rpc:
    def __init__(self, url):
        self.url = url

    def __call__(self, method, params, tries=6, quiet=False):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        for attempt in range(tries):
            try:
                req = urllib.request.Request(
                    self.url, data=body.encode(), headers={"Content-Type": "application/json"}
                )
                with urllib.request.urlopen(req, timeout=180) as r:
                    out = json.loads(r.read())
                if "error" in out:
                    raise RuntimeError(str(out["error"])[:200])
                return out["result"]
            except Exception:
                if attempt == tries - 1:
                    if quiet:
                        return None
                    raise
                time.sleep(2 * (attempt + 1))


def progress(msg):
    sys.stderr.write("\r" + msg + " " * 12)
    sys.stderr.flush()


def path(args, name):
    os.makedirs(args.out, exist_ok=True)
    return os.path.join(args.out, name)


def cmd_population(args, rpc):
    """Every Program account owned by the upgradeable loader.

    A Program account is exactly 36 bytes (a 4-byte enum plus the ProgramData
    address), which makes `dataSize` a precise filter for "is a program" and keeps
    the response small enough for a public endpoint to serve.
    """
    res = rpc(
        "getProgramAccounts",
        [
            LOADER,
            {
                "encoding": "base64",
                "dataSlice": {"offset": 0, "length": 0},
                "filters": [{"dataSize": 36}],
            },
        ],
    )
    ids = [a["pubkey"] for a in res]
    json.dump(ids, open(path(args, "population.json"), "w"))
    print(f"upgradeable program accounts: {len(ids):,}")


def cmd_active(args, rpc):
    """Programs actually invoked in recent blocks, counted by invocation.

    Sampling by invocation rather than by existence is the whole point: most
    deployed programs are abandoned, and a census that treats them equally
    describes a graveyard rather than the network.
    """
    counts = Counter()
    tip = rpc("getSlot", [])
    blocks = 0
    for i in range(args.blocks):
        slot = tip - 60 - i * args.stride
        blk = rpc(
            "getBlock",
            [
                slot,
                {
                    "encoding": "json",
                    "transactionDetails": "full",
                    "maxSupportedTransactionVersion": 0,
                    "rewards": False,
                },
            ],
            quiet=True,
        )
        if not blk:
            continue
        blocks += 1
        for tx in blk["transactions"]:
            msg = tx["transaction"]["message"]
            meta = tx.get("meta") or {}
            keys = list(msg["accountKeys"])
            loaded = meta.get("loadedAddresses") or {}
            keys += loaded.get("writable", []) + loaded.get("readonly", [])
            groups = [msg.get("instructions", [])]
            groups += [g.get("instructions", []) for g in (meta.get("innerInstructions") or [])]
            for group in groups:
                for ins in group:
                    idx = ins.get("programIdIndex")
                    if idx is not None and idx < len(keys):
                        counts[keys[idx]] += 1
        progress(f"blocks {blocks}/{args.blocks}  distinct {len(counts)}")
    sys.stderr.write("\n")
    json.dump(counts.most_common(), open(path(args, "active-counts.json"), "w"))
    print(f"tip slot {tip}  blocks {blocks}  distinct {len(counts)}  invocations {sum(counts.values()):,}")


def cmd_headers(args, rpc):
    """Read the 45-byte ProgramData header (slot + authority) for a set of programs."""
    if args.population == "active":
        ids = [p for p, _ in json.load(open(path(args, "active-counts.json")))]
    else:
        ids = json.load(open(path(args, "population.json")))
        random.seed(args.seed)
        ids = random.sample(ids, args.sample)

    pdas = [(pid, programdata_address(pid)) for pid in ids]
    out = {}
    missing = 0
    for i in range(0, len(pdas), 100):
        chunk = pdas[i : i + 100]
        res = rpc(
            "getMultipleAccounts",
            [
                [a for _, a in chunk],
                {"encoding": "base64", "dataSlice": {"offset": 0, "length": 45}},
            ],
        )["value"]
        for (pid, _), acc in zip(chunk, res):
            if not acc:
                missing += 1
                continue
            raw = base64.b64decode(acc["data"][0])
            # ProgramData: u32 discriminant (3) | u64 last deploy slot | Option<Pubkey>
            if len(raw) < 13 or int.from_bytes(raw[0:4], "little") != 3:
                missing += 1
                continue
            slot = int.from_bytes(raw[4:12], "little")
            authority = b58_encode(raw[13:45]) if raw[12] == 1 and len(raw) >= 45 else None
            out[pid] = [slot, authority]
        progress(f"{args.population}: {min(i + 100, len(pdas))}/{len(pdas)}")
    sys.stderr.write("\n")
    json.dump(out, open(path(args, f"headers-{args.population}.json"), "w"))
    print(f"{args.population}: requested {len(ids)}, resolved {len(out)}, no ProgramData {missing}")


def seconds_per_slot(rpc, tip, span):
    """Measure it rather than assuming 400 ms — every age in the report divides by this."""
    recent = rpc("getBlockTime", [tip - 100])
    probe, old = tip - span, None
    while old is None and probe < tip:
        old = rpc("getBlockTime", [probe], quiet=True)
        probe += 1
    return (recent - old) / (tip - 100 - (probe - 1))


def classify(rows, tip, sec_per_slot):
    wallet = pda = immutable = 0
    ages = []
    for _pid, (slot, authority) in rows:
        if authority is None:
            immutable += 1
        elif on_curve(b58_decode(authority)):
            wallet += 1
        else:
            pda += 1
        ages.append((tip - slot) * sec_per_slot / 86400)
    ages.sort()
    n = len(ages)
    return {
        "n": n,
        "wallet": wallet,
        "pda": pda,
        "immutable": immutable,
        "median_age_days": round(ages[n // 2], 1),
        "p10": round(ages[n // 10], 1),
        "p90": round(ages[n * 9 // 10], 1),
        "within_30d": sum(1 for a in ages if a <= 30),
        "within_90d": sum(1 for a in ages if a <= 90),
    }


def cmd_report(args, rpc):
    tip = rpc("getSlot", [])
    sps = seconds_per_slot(rpc, tip, args.calibrate_span)
    print(f"tip slot {tip}")
    print(f"calibration: {sps:.4f} s/slot measured over {args.calibrate_span:,} slots\n")

    counts = dict(json.load(open(path(args, "active-counts.json"))))
    active = json.load(open(path(args, "headers-active.json")))
    ranked = sorted(active.items(), key=lambda kv: -counts.get(kv[0], 0))

    buckets = [(f"top {k} by calls", ranked[:k]) for k in (25, 50, 100)]
    buckets.append((f"all invoked ({len(ranked)})", ranked))
    try:
        rnd = json.load(open(path(args, "headers-all.json")))
        buckets.append((f"random sample ({len(rnd)})", list(rnd.items())))
    except FileNotFoundError:
        pass

    header = f"{'population':<24}{'n':>5}{'wallet':>14}{'program':>14}{'immut':>7}{'median':>9}{'<=30d':>11}{'<=90d':>11}"
    print(header)
    print("-" * len(header))
    out = {}
    for name, rows in buckets:
        s = classify(rows, tip, sps)
        out[name] = s
        n = s["n"]
        print(
            f"{name:<24}{n:>5}"
            f"{s['wallet']:>8} ({s['wallet'] * 100 // n:>2}%)"
            f"{s['pda']:>8} ({s['pda'] * 100 // n:>2}%)"
            f"{s['immutable']:>7}"
            f"{s['median_age_days']:>8.0f}d"
            f"{s['within_30d']:>6} ({s['within_30d'] * 100 // n:>2}%)"
            f"{s['within_90d']:>6} ({s['within_90d'] * 100 // n:>2}%)"
        )
    json.dump({"tip": tip, "sec_per_slot": sps, "buckets": out}, open(path(args, "report.json"), "w"))


def cmd_churn(args, rpc):
    """Successful transactions touching ProgramData in the trailing year.

    An upgrade is one such transaction, and so is a `set-upgrade-authority` and an
    `extend-program`; the count is therefore an upper bound on redeploys rather than
    an exact one. It is reported alongside the independent age snapshot for that reason.
    """
    counts = dict(json.load(open(path(args, "active-counts.json"))))
    active = json.load(open(path(args, "headers-active.json")))
    ranked = sorted(active, key=lambda p: -counts.get(p, 0))[: args.top]

    cutoff = time.time() - 365 * 86400
    rows = []
    for i, pid in enumerate(ranked):
        addr = programdata_address(pid)
        sigs, before, seen = [], None, 0
        while True:
            params = [addr, {"limit": 1000}]
            if before:
                params[1]["before"] = before
            page = rpc("getSignaturesForAddress", params, quiet=True)
            if not page:
                break
            sigs += page
            seen += len(page)
            oldest = page[-1].get("blockTime") or 0
            if len(page) < 1000 or oldest < cutoff or seen > args.max_signatures:
                break
            before = page[-1]["signature"]
        ok = [s for s in sigs if not s.get("err") and (s.get("blockTime") or 0) >= cutoff]
        rows.append([pid, len(ok), counts.get(pid, 0)])
        progress(f"churn {i + 1}/{len(ranked)}")
    sys.stderr.write("\n")

    per = sorted(r[1] for r in rows)
    n = len(per)
    print(f"busiest programs sampled: {n}")
    print(f"ProgramData writes in trailing 365d — median {per[n // 2]}, mean {sum(per) / n:.1f}, max {per[-1]}")
    for label, lo, hi in (("0 (untouched)", 0, 0), ("1-3", 1, 3), ("4-11", 4, 11), ("12+", 12, 10**9)):
        c = sum(1 for x in per if lo <= x <= hi)
        print(f"  {label:<16} {c:>3} programs ({c * 100 // n:>2}%)")
    json.dump(rows, open(path(args, "churn.json"), "w"))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rpc", default="https://api.mainnet-beta.solana.com")
    ap.add_argument("--out", default="./census-data")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("population")

    a = sub.add_parser("active")
    a.add_argument("--blocks", type=int, default=25)
    a.add_argument("--stride", type=int, default=40)

    h = sub.add_parser("headers")
    h.add_argument("population", choices=["all", "active"])
    h.add_argument("sample", nargs="?", type=int, default=2000)
    h.add_argument("--seed", type=int, default=20260729)

    r = sub.add_parser("report")
    r.add_argument("--calibrate-span", type=int, default=50_000_000)

    c = sub.add_parser("churn")
    c.add_argument("top", nargs="?", type=int, default=60)
    c.add_argument("--max-signatures", type=int, default=5000)

    args = ap.parse_args()
    globals()[f"cmd_{args.cmd}"](args, Rpc(args.rpc))


if __name__ == "__main__":
    main()
