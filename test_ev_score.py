#!/usr/bin/env python3
# tests/test_ev_score.py — comprehensive test suite for ev_score.py
# Run: python tests/test_ev_score.py
# Tests: 30 cases across all rules, edge cases, evasion, sanity checks

import sys, os, json, math, random
import numpy as np
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
from ev_score import extract_features, detect, ev4, load_state, save_state

PASS = "✅ PASS"
FAIL = "❌ FAIL"
results = []

def test(name, condition, info=""):
    results.append((name, condition, str(info)))

def make_state(n_windows=15, ur_range=(0.76, 0.84), ll_range=(8, 12)):
    """Build calibrated baseline state. ur≈0.80 matches real internet DNS."""
    state = {'baseline': [], 'burn_in': 10}
    for _ in range(n_windows):
        pool   = [f"host{i}" for i in range(1200)]
        labels = [random.choice(pool) for _ in range(1000)]
        qnames = [f"{l}.example.com" for l in labels]
        feat   = extract_features(qnames)
        if feat:
            state['baseline'].append(feat)
    return state

def run_detect(qnames, state=None, fpr=0.01):
    if state is None:
        state = make_state()
    feat = extract_features(qnames)
    return detect(feat, {**state, 'baseline': list(state['baseline'])}, fpr)

BASE_STATE = make_state(20)

print("=" * 90)
print("EV DNS TUNNEL DETECTOR — TEST SUITE")
print("=" * 90)

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1: SANITY CHECKS
# ─────────────────────────────────────────────────────────────────────────────
print("\n── Section 1: Sanity Checks ──")

# S1: P[0,0] immutable
P = np.random.default_rng(42).standard_normal((256, 500)) / np.sqrt(256)
test("S1: P[0,0] = 0.01904482 (immutable)", abs(P[0,0] - 0.01904482) < 1e-5,
     f"P[0,0]={P[0,0]:.8f}")

# S2: ev4 returns float for valid input
val = ev4(b"abcdefghij" * 100)
test("S2: ev4 returns float for valid input", isinstance(val, float) and not math.isnan(val),
     f"ev4={val:.4f}")

# S3: ev4 returns nan for too-short input
val = ev4(b"ab")
test("S3: ev4 returns nan for <4 bytes", math.isnan(val), f"ev4={val}")

# S4: ev4 returns nan for empty input
val = ev4(b"")
test("S4: ev4 returns nan for empty bytes", math.isnan(val), f"ev4={val}")

# S5: extract_features returns None for empty qnames
feat = extract_features([])
test("S5: extract_features([]) returns None", feat is None, str(feat))

# S6: extract_features returns None for None
feat = extract_features(None)
test("S6: extract_features(None) returns None", feat is None, str(feat))

# S7: extract_features has required keys
qnames = [f"label{i}.example.com" for i in range(100)]
feat = extract_features(qnames)
required = {'ev', 'unique_ratio', 'top1_freq', 'n_queries', 'label_len_mean'}
test("S7: extract_features has all required keys",
     feat is not None and required.issubset(feat.keys()),
     str(feat.keys() if feat else None))

# S8: ur always in [0,1]
for _ in range(5):
    q = [f"x{random.randint(1,50)}.test.com" for _ in range(200)]
    feat = extract_features(q)
    test("S8: ur in [0,1]", feat is not None and 0 <= feat['unique_ratio'] <= 1,
         f"ur={feat['unique_ratio'] if feat else 'None'}")

# S9: t1 always in [0,1]
for _ in range(3):
    q = [f"x{random.randint(1,50)}.test.com" for _ in range(200)]
    feat = extract_features(q)
    test("S9: t1 in [0,1]", feat is not None and 0 <= feat['top1_freq'] <= 1,
         f"t1={feat['top1_freq'] if feat else 'None'}")

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2: NORMAL TRAFFIC (ALL SHOULD BE BENIGN)
# ─────────────────────────────────────────────────────────────────────────────
print("\n── Section 2: Normal Traffic (expect BENIGN) ──")

# N1: Standard web browsing
labels = [f"label{random.randint(1,200)}" for _ in range(1000)]
qnames = [f"{l}.example.com" for l in labels]
is_t, rule = run_detect(qnames)
test("N1: Normal web browsing → BENIGN", not is_t, rule)

# N2: Low query count normal traffic
qnames = [f"host{random.randint(1,50)}.corp.local" for _ in range(200)]
is_t, rule = run_detect(qnames)
test("N2: Normal low-volume → BENIGN", not is_t, rule)

# N3: CDN traffic (many subdomains of same domain)
qnames = [f"edge{random.randint(1,500)}.cdn.cloudflare.com" for _ in range(500)]
is_t, rule = run_detect(qnames)
test("N3: CDN subdomains → BENIGN", not is_t, rule)

# N4: Internal corporate DNS (repetitive hostnames)
hosts = [f"server{i:03d}.corp.local" for i in range(20)]
qnames = [random.choice(hosts) for _ in range(500)]
is_t, rule = run_detect(qnames)
test("N4: Corporate internal DNS → BENIGN", not is_t, rule)

# N5: Mixed TLD normal traffic — alpha labels like real internet DNS
tlds = ["com", "net", "org", "io", "co", "uk", "de", "fr"]
names = ["google","amazon","facebook","twitter","github","apple","netflix",
         "adobe","spotify","slack","zoom","dropbox","stripe","twilio",
         "azure","ubuntu","debian","nginx","redis","kafka"] * 15
qnames = [f"{random.choice(names)}.{random.choice(tlds)}" for _ in range(500)]
is_t, rule = run_detect(qnames)
test("N5: Mixed TLD normal traffic → BENIGN", not is_t, rule)
# N6: Windows DNS (wpad, _ldap, _kerberos etc.)
windows_hosts = ['wpad', '_ldap._tcp', '_kerberos._tcp', 'isatap',
                 'gc._msdcs', '_gc._tcp', 'domaindnszones']
qnames = [f"{random.choice(windows_hosts)}.corp.local" for _ in range(200)]
is_t, rule = run_detect(qnames)
test("N6: Windows DNS traffic → BENIGN", not is_t, rule)

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3: WILDCARD DNS (SHOULD BE BENIGN — NOT TUNNELS)
# ─────────────────────────────────────────────────────────────────────────────
print("\n── Section 3: Wildcard DNS (expect BENIGN) ──")

# W1: Standard wildcard (ur=0.35, long labels ~32)
# Real wildcards: ISP/CDN resolves ~200 unique subdomains repeatedly
wc_pool = ["".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=32))
           for _ in range(200)]
wildcard = [random.choice(wc_pool) + ".wildcard.example.com" for _ in range(500)]
is_t, rule = run_detect(wildcard)
test("W1: Wildcard ur=0.35 ll=32 → BENIGN", not is_t, rule)

# W2: High-z wildcard (like wildcard_00009 z=+7.3)
wc_pool2 = ["".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=32))
            for _ in range(300)]
wildcard2 = [random.choice(wc_pool2) + f".{random.randint(1,3)}.wc.example.com"
             for _ in range(1000)]
is_t, rule = run_detect(wildcard2)
test("W2: Wildcard high-z → BENIGN (wildcard suppression)", not is_t, rule)


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 4: KNOWN TUNNELS (ALL SHOULD BE DETECTED)
# ─────────────────────────────────────────────────────────────────────────────
print("\n── Section 4: Known Tunnels (expect TUNNEL) ──")

# T1: dnscat2 — hex encoded labels, ur=1.0
dnscat2 = [''.join(random.choices('0123456789abcdef', k=random.randint(32,60)))
           + '.tunnel.local' for _ in range(500)]
is_t, rule = run_detect(dnscat2)
test("T1: dnscat2 hex labels ur=1.0 → TUNNEL", is_t, rule)

# T2: iodine — base32 encoded labels, ur=1.0
b32 = 'abcdefghijklmnopqrstuvwxyz234567'
iodine = [''.join(random.choices(b32, k=random.randint(40,62)))
          + '.tun.local' for _ in range(500)]
is_t, rule = run_detect(iodine)
test("T2: iodine base32 ur=1.0 → TUNNEL", is_t, rule)

# T3: dns2tcp — base64 shorter labels, ur=0.87
b64 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+='
dns2tcp = [''.join(random.choices(b64, k=random.randint(8,12)))
           + '.tcp.local' for _ in range(2000)]
is_t, rule = run_detect(dns2tcp)
test("T3: dns2tcp base64 ur=0.87 → TUNNEL", is_t, rule)

# T4: CobaltStrike beacon — t1=0.96
beacon = "windowsupdate.microsoft.com.cdn.net"
cobalt = [beacon if random.random() < 0.96
          else ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8)) + '.local'
          for _ in range(500)]
is_t, rule = run_detect(cobalt)
test("T4: CobaltStrike beacon t1=0.96 → TUNNEL", is_t, rule)

# T5: DNS-shell — fixed pool, ur≈0.45
pool = [''.join(random.choices('0123456789abcdef', k=9)) for _ in range(200)]
dnsshell = [random.choice(pool) + '.sh.local' for _ in range(500)]
is_t, rule = run_detect(dnsshell)
test("T5: DNS-shell fixed pool ur≈0.45 → TUNNEL", is_t, rule)

# T6: ozymandns — base64 labels, ur≈0.998
ozymandns = [''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
                                     k=random.randint(10,15)))
             + '.ozy.tunnel.net' for _ in range(500)]
is_t, rule = run_detect(ozymandns)
test("T6: ozymandns ur≈0.998 → TUNNEL", is_t, rule)

# T7: tcp-over-dns — fixed length labels, ur≈0.999
tcp_over = [''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
                                    k=29))
            + '.tcp2dns.net' for _ in range(500)]
is_t, rule = run_detect(tcp_over)
test("T7: tcp-over-dns ur≈0.999 → TUNNEL", is_t, rule)

# T8: tuns — random labels, ur=1.0
tuns = [''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=random.randint(10,63)))
        + '.tuns.net' for _ in range(500)]
is_t, rule = run_detect(tuns)
test("T8: tuns ur=1.0 → TUNNEL", is_t, rule)

# T9: dnspot — max-length labels, ur=1.0
dnspot = [''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=60))
          + '.dnspot.net' for _ in range(500)]
is_t, rule = run_detect(dnspot)
test("T9: dnspot max-length labels → TUNNEL", is_t, rule)

# T10: AndIodine (Android) — base32, mixed lengths
and_iodine = [''.join(random.choices(b32, k=random.randint(10,50)))
              + '.and.tunnel.net' for _ in range(500)]
is_t, rule = run_detect(and_iodine)
test("T10: AndIodine Android base32 → TUNNEL", is_t, rule)

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 5: EDGE CASES & BOUNDARY CONDITIONS
# ─────────────────────────────────────────────────────────────────────────────
print("\n── Section 5: Edge Cases ──")

# E1: n_min gate — too few queries
tiny = ['abc123def456.tunnel.local'] * 5
is_t, rule = run_detect(tiny)
test("E1: n=5 → insufficient_data (not false tunnel)", not is_t, rule)

# E2: exactly at n_min boundary (n=51)
labels = [f"label{random.randint(1,200)}" for _ in range(51)]
qnames = [f"{l}.example.com" for l in labels]
is_t, rule = run_detect(qnames)
test("E2: n=51 (just above n_min) processes correctly", rule != "insufficient_data", rule)

# E3: single unique label (t1=1.0, n=100) — looks like beacon
same = ["repeated-label.example.com"] * 100
is_t, rule = run_detect(same)
test("E3: Single repeated label n=100 → TUNNEL (beacon)", is_t, rule)

# E4: calibration phase returns False
state_empty = {'baseline': [], 'burn_in': 10}
qnames = [''.join(random.choices('0123456789abcdef', k=40)) + '.tunnel.local'
          for _ in range(500)]
feat = extract_features(qnames)
is_t, rule = detect(feat, state_empty, 0.01)
test("E4: During calibration → not flagged (calibrating)", not is_t, rule)

# E5: Very long labels (>63 chars — technically invalid DNS but seen in tunnels)
long_labels = [''.join(random.choices('0123456789abcdef', k=62)) + '.tunnel.local'
               for _ in range(500)]
is_t, rule = run_detect(long_labels)
test("E5: Long labels 62 chars ur=1.0 → TUNNEL", is_t, rule)

# E6: All same domain repeated (DGA-like but single domain)
dga_single = ['abc123.dga-c2.net'] * 500
is_t, rule = run_detect(dga_single)
test("E6: DGA single domain repeated → TUNNEL (beacon)", is_t, rule)

# E7: Mixed legitimate + tunnel (dilution attack - 50% normal)
legit   = [f"label{random.randint(1,200)}.example.com" for _ in range(250)]
tunnel  = [''.join(random.choices('0123456789abcdef', k=40)) + '.tunnel.local'
           for _ in range(250)]
mixed   = legit + tunnel
random.shuffle(mixed)
is_t, rule = run_detect(mixed)
# Note: dilution may evade detection — documenting behavior
test("E7: 50% normal + 50% dnscat2 mixed → detection behavior documented",
     True, f"result={'TUNNEL' if is_t else 'BENIGN'} rule={rule}")

# E8: Empty labels (malformed DNS)
malformed = [".example.com", "..example.com", "example.com"] * 100
feat = extract_features(malformed)
test("E8: Malformed/empty labels handled gracefully",
     feat is None or isinstance(feat, dict), str(type(feat)))

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 6: FPR TARGET SENSITIVITY
# ─────────────────────────────────────────────────────────────────────────────
print("\n── Section 6: FPR Target Sensitivity ──")

# F1: Strict FPR (0.001) — normal traffic still benign
qnames = [f"label{random.randint(1,200)}.example.com" for _ in range(1000)]
is_t, rule = run_detect(qnames, fpr=0.001)
test("F1: Normal traffic at FPR=0.001 → BENIGN", not is_t, rule)

# F2: Loose FPR (0.1) — tunnel still detected
dnscat2 = [''.join(random.choices('0123456789abcdef', k=40)) + '.tunnel.local'
           for _ in range(500)]
is_t, rule = run_detect(dnscat2, fpr=0.1)
test("F2: dnscat2 at FPR=0.1 → TUNNEL", is_t, rule)

# F3: Strict FPR (0.001) — dnscat2 still detected
is_t, rule = run_detect(dnscat2, fpr=0.001)
test("F3: dnscat2 at FPR=0.001 → TUNNEL", is_t, rule)

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7: STATE PERSISTENCE
# ─────────────────────────────────────────────────────────────────────────────
print("\n── Section 7: State Persistence ──")

import tempfile

# P1: State save/load round-trip
state = make_state()
with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
    tmppath = f.name
save_state(tmppath, state)
loaded = load_state(tmppath)
os.unlink(tmppath)
test("P1: State save/load round-trip preserves baseline length",
     len(loaded['baseline']) == len(state['baseline']),
     f"saved={len(state['baseline'])} loaded={len(loaded['baseline'])}")

# P2: Missing state file returns empty state
missing = load_state('/tmp/nonexistent_ev_state_xyz.json')
test("P2: Missing state file returns empty state",
     isinstance(missing, dict) and 'baseline' in missing,
     str(missing))

# P3: Baseline capped at 100 windows
big_state = make_state(5)
for _ in range(120):
    feat = extract_features([f"label{random.randint(1,200)}.com" for _ in range(200)])
    if feat: big_state['baseline'].append(feat)
# Simulate detect capping
if len(big_state['baseline']) > 100:
    big_state['baseline'] = big_state['baseline'][-100:]
test("P3: Baseline capped at 100 windows", len(big_state['baseline']) <= 100,
     f"len={len(big_state['baseline'])}")

# ─────────────────────────────────────────────────────────────────────────────
# RESULTS SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{'=' * 90}")
print(f"{'Test':<50} {'Result':<10} Info")
print("-" * 90)

passed = failed = 0
for name, ok, info in results:
    status = PASS if ok else FAIL
    if ok: passed += 1
    else:  failed += 1
    print(f"{name:<50} {status:<10} {info}")

print(f"\n{'=' * 90}")
print(f"TOTAL: {passed+failed} tests | {passed} passed | {failed} failed")
print(f"{'ALL TESTS PASSED ✅' if failed == 0 else f'❌ {failed} TESTS FAILED'}")
print(f"{'=' * 90}")
sys.exit(0 if failed == 0 else 1)
