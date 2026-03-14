#!/usr/bin/env python3
# ev_score.py — DNS tunnel scorer called by Zeek
# Reads qnames from file, returns JSON verdict
# Self-calibrating: state persisted across calls

import numpy as np
from scipy.stats import skew as scipy_skew, beta as beta_dist
import json, argparse, os, sys, math

# ── Canonical Ev formula (immutable) ─────────────────────────────────────────
P4 = np.random.default_rng(42).standard_normal((256, 500)) / np.sqrt(256)
assert abs(P4[0,0] - 0.01904482) < 1e-5, "WRONG RNG"
PRIMES = [p for p in range(2,500) if all(p%i!=0 for i in range(2,int(p**0.5)+1))][:95]

def ev4(data: bytes) -> float:
    if len(data) < 4: return float('nan')
    b = (np.frombuffer(data, dtype=np.uint8) // 64).astype(np.int32)
    v = np.bincount(b[:-3]*64+b[1:-2]*16+b[2:-1]*4+b[3:], minlength=256).astype(float)
    s = v.sum()
    if s == 0: return float('nan')
    return float(abs(scipy_skew(((v/s) @ P4)[PRIMES])))

def extract_features(qnames):
    if not qnames: return None
    labels = [q.split('.')[0] for q in qnames]
    ev = ev4(''.join(qnames).lower().encode())
    if math.isnan(ev): return None
    n  = len(labels)
    ur = len(set(labels)) / n
    t1 = max(labels.count(l) for l in set(labels)) / n
    ll = float(np.mean([len(l) for l in labels]))
    return {'ev': round(ev,4), 'unique_ratio': round(ur,3),
            'top1_freq': round(t1,3), 'n_queries': n, 'label_len_mean': round(ll,2)}

def load_state(path):
    try:
        return json.load(open(path))
    except:
        return {'baseline': [], 'burn_in': 10}

def save_state(path, state):
    json.dump(state, open(path, 'w'))

def detect(features, state, fpr_target=0.01):
    if features is None:
        return False, "insufficient_data"

    n  = features['n_queries']
    ur = features['unique_ratio']
    t1 = features['top1_freq']
    ev = features['ev']
    ll = features.get('label_len_mean', 0)
    baseline = state.get('baseline', [])
    burn_in  = state.get('burn_in', 10)
    k = 1.0 / math.sqrt(fpr_target)

    # n_min: std(ur) < 0.05 → n > ur*(1-ur)/0.05²
    n_min = max(10.0, ur * (1-ur) / 0.0025)
    if n < n_min:
        return False, f"insufficient_data(n={n:.0f})"

    if len(baseline) < burn_in:
        baseline.append(features)
        state['baseline'] = baseline
        return False, f"calibrating({len(baseline)}/{burn_in})"

    obs_ur  = np.array([w['unique_ratio'] for w in baseline])
    obs_ev  = np.array([w['ev']           for w in baseline])
    obs_t1n = np.array([w['top1_freq'] * math.sqrt(w['n_queries']) for w in baseline])

    # Rule 1: Beacon — Chebyshev on t1*sqrt(n)
    t1n = t1 * math.sqrt(n)
    bt_mu  = obs_t1n.mean()
    bt_std = max(obs_t1n.std(), bt_mu * 0.2, 0.5)  # floor: std >= 20% of mean or 0.5
    beacon_thresh = bt_mu + k * bt_std
    if t1n > beacon_thresh:
        return True, f"beacon(t1√n={t1n:.1f}>{beacon_thresh:.1f})"

    # Rule 2: High ur — exact Beta CI
    ur_max    = obs_ur.max()
    k_max     = int(ur_max * n)
    ur_thresh = beta_dist.ppf(1 - fpr_target, k_max + 1, max(1, n - k_max))
    # Suppress wildcards: ur<0.55 AND label_len>28 (structural, not statistical)
    is_wildcard = ur < 0.55 and ll > 28
    if ur > ur_thresh and not is_wildcard:
        return True, f"high_ur(ur={ur:.3f}>{ur_thresh:.3f})"

    # Rule 3: Ev excess — Gaussian 3σ
    obs_urn = np.array([w['unique_ratio'] for w in baseline])
    if obs_urn.std() > 0.01:
        coeffs       = np.polyfit(obs_urn, obs_ev, 1)
        ev_expected  = coeffs[1] + coeffs[0] * ur
        ev_residuals = obs_ev - (coeffs[1] + coeffs[0] * obs_urn)
    else:
        ev_expected  = obs_ev.mean()
        ev_residuals = obs_ev - obs_ev.mean()
    sigma = max(ev_residuals.std(), 0.015)  # floor from real-world Ev excess std=0.0184
    ev_excess = ev - ev_expected
    is_wildcard = ur < 0.55 and ll > 28
    if ev_excess > 3.0 * sigma and not is_wildcard:
        return True, f"ev_excess({ev_excess:+.3f}>{3.0*sigma:.3f})"

    # Update baseline with confirmed normal window
    baseline.append(features)
    state['baseline'] = baseline[-100:]  # keep last 100 windows
    return False, "normal"


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--qfile',  required=True)
    parser.add_argument('--state',  required=True)
    parser.add_argument('--fpr',    type=float, default=0.01)
    args = parser.parse_args()

    qnames   = [l.strip() for l in open(args.qfile) if l.strip()]
    features = extract_features(qnames)
    state    = load_state(args.state)

    is_tunnel, rule = detect(features, state, args.fpr)
    save_state(args.state, state)

    result = {
        'is_tunnel': is_tunnel,
        'rule':      rule,
        'features':  features or {}
    }
    print(json.dumps(result))
