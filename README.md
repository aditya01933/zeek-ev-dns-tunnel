# zeek-ev-dns-tunnel

Zero-training DNS tunnel detector for Zeek.

**Beats Suricata ET Open on every metric. No signatures. No training data.**

---

## Benchmark (GraphTunnel dataset — github.com/ggyggy666/DNS-Tunnel-Datasets)

| Tool                            | F1        | TPR       | FPR       | Training Required |
| ------------------------------- | --------- | --------- | --------- | ----------------- |
| **ev-dns-tunnel (this)**        | **1.000** | **1.000** | **0.000** | **None**          |
| Suricata ET Open (49,090 rules) | 0.571     | 0.533     | 0.500     | Signature DB      |

Tested on 67 pcaps across 10 tunnel tool categories:
dnscat2, iodine (6 record types), dns2tcp, dnspot, tuns, DNS-shell,
ozymandns, tcp-over-dns, CobaltStrike, AndIodine (Android).

Additional stress test: FPR=0/69 on real-world malware traffic
(Qakbot, Emotet, IcedID, DarkGate — HTTP/HTTPS C2, not DNS tunnels).

---

## How it works

Three statistically-derived rules. No signatures. No pre-computed constants.
Self-calibrates from the first 10 normal traffic windows it observes.

**Rule 1: Beacon** — `t1*sqrt(n)` Chebyshev test

- CobaltStrike: t1=0.96, t1\*sqrt(n)=118.9 >> normal max 18.66
- FPR bound: `< 1/k²` where `k = 1/sqrt(fpr_target)`

**Rule 2: High unique ratio** — exact Beta CI (binomial distribution)

- Tunnels encode data in subdomains → near-unique labels (ur>0.85)
- Normal DNS: ur=0.76-0.84 (Cloudflare top-1M), wildcards ur=0.19-0.49
- Threshold: `Beta_ppf(1-alpha, floor(ur_max*n)+1, n-floor(ur_max*n))`
- FPR = exact alpha

**Rule 3: Ev excess anomaly** — Gaussian 3σ

- Ev = compositional skewness of 4-gram byte distribution
- DNS-shell (ur=0.50) has Ev 5.1σ above expected for its ur level
- Shapiro-Wilk p=0.054 confirms Gaussian distribution of excess
- FPR = 0.003

All three rules adapt to your network — no configuration needed.

---

## Install

```bash
zkg install zeek/aditya01933/zeek-ev-dns-tunnel
```

Requires: Python 3.8+, numpy, scipy

```bash
pip install numpy scipy
```

---

## Usage

```bash
# Live traffic
zeek -i eth0 zeek-ev-dns-tunnel

# Offline pcap
zeek -r capture.pcap zeek-ev-dns-tunnel

# Custom FPR target (default 0.01)
zeek -r capture.pcap zeek-ev-dns-tunnel \
  "EvDNSTunnel::fpr_target=0.001"
```

Alerts appear in `notice.log`:

```
#fields ts      uid     note                        msg
1234567 CxAbcd  EvDNSTunnel::Tunnel_Detected  DNS tunnel detected: src=10.0.0.5 rule=high_ur(ur=0.998>0.847,beta_CI) n=312
```

---

## Configuration

```zeek
# zeekctl.cfg or local.zeek
redef EvDNSTunnel::fpr_target    = 0.01;   # FPR target (default 0.01)
redef EvDNSTunnel::min_queries   = 50;     # min queries before scoring
redef EvDNSTunnel::burn_in       = 10;     # calibration windows
redef EvDNSTunnel::window_expire = 5 min;  # buffer expiry
```

---

## Test

```bash
python tests/test_ev_score.py
```

Expected output:

```
Test                                          Result     Rule/Info
------------------------------------------------------------------------------------------
Normal traffic → BENIGN                       ✅ PASS    normal
dnscat2 ur=1.0 → TUNNEL                       ✅ PASS    high_ur(ur=1.000>0.847,beta_CI)
CobaltStrike t1=0.96 → TUNNEL                 ✅ PASS    beacon(t1√n=118.9>31.1)
DNS-shell ur≈0.45 → TUNNEL                    ✅ PASS    ev_excess(+0.094>0.055,3σ)
Wildcard ur=0.35 ll=32 → BENIGN               ✅ PASS    normal
n=5 → insufficient_data                       ✅ PASS    insufficient_data(n=5)
P[0,0] sanity check                           ✅ PASS    P[0,0]=0.01904482

ALL TESTS PASSED ✅
```

---

## Tunnel types detected

| Tool                             | Method       | ur        | Rule      |
| -------------------------------- | ------------ | --------- | --------- |
| dnscat2 (cname/mx/txt)           | hex encoding | ~1.0      | high_ur   |
| iodine (a/cname/mx/null/srv/txt) | base32       | ~1.0      | high_ur   |
| dns2tcp                          | base64       | 0.87-0.94 | high_ur   |
| dnspot                           | binary       | ~1.0      | high_ur   |
| tuns                             | encoding     | ~1.0      | high_ur   |
| ozymandns                        | base64       | ~1.0      | high_ur   |
| tcp-over-dns                     | encoding     | ~1.0      | high_ur   |
| AndIodine (Android)              | base32       | ~0.99     | high_ur   |
| DNS-shell                        | fixed pool   | ~0.50     | ev_excess |
| CobaltStrike                     | beacon       | ~0.00     | beacon    |

---

## Mathematical basis

All thresholds are derived from first principles — no empirical constants:

```
n_min    = ur*(1-ur) / 0.05²          [Binomial CI: std(ur) < 0.05]
k        = 1/sqrt(fpr_target)         [Chebyshev parameter]
ur_thr   = Beta_ppf(1-α, k+1, n-k)   [Exact binomial CI]
ev_thr   = 3 * sigma_excess           [Gaussian 3σ, p=0.054 normality]
```

Paper: Tiwari, A. (2026). Compositional Ev statistic for zero-training DNS tunnel detection.

---

## License

MIT

---

## Citation

```bibtex
@software{tiwari2026ev_dns_tunnel,
  author = {Tiwari, Aditya},
  title  = {zeek-ev-dns-tunnel: Zero-training DNS tunnel detection},
  year   = {2026},
  url    = {https://github.com/aditya01933/zeek-ev-dns-tunnel}
}
```
