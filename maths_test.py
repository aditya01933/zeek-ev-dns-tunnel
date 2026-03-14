#!/usr/bin/env python3
"""Deep mathematical analysis of the Ev formula"""
import numpy as np
from scipy.stats import skew, kurtosis, entropy, spearmanr
from scipy.special import comb
import time

RNG = np.random.default_rng(42)
P = RNG.standard_normal((256, 500)) / np.sqrt(256)
assert abs(P[0,0] - 0.01904482) < 1e-5

PRIMES = [p for p in range(2, 500) if all(p%i!=0 for i in range(2, int(p**0.5)+1))][:95]
NON_PRIMES = [i for i in range(2, 500) if i not in PRIMES][:95]
EVENS = list(range(2, 192, 2))[:95]
ODDS = list(range(1, 191, 2))[:95]
RANDOM_IDX = sorted(RNG.choice(500, 95, replace=False))
CONSECUTIVE = list(range(95))
FIBONACCI = [1,2,3,5,8,13,21,34,55,89,144,233,377]  # extend to 95
fib_set = set()
a, b = 1, 2
while len(fib_set) < 95 and b < 500:
    fib_set.add(b); a, b = b, a+b
# Not enough fibs — pad with primes
FIBONACCI = sorted(list(fib_set))[:min(len(fib_set), 95)]

def compute_ev(seq_str, indices=PRIMES):
    """Compute Ev for a string sequence using given index set"""
    # 4-mer frequencies
    counts = np.zeros(256)
    for i in range(len(seq_str) - 3):
        idx = 0
        for j in range(4):
            c = seq_str[i+j]
            if c == 'A': b = 0
            elif c == 'C': b = 1
            elif c == 'G': b = 2
            elif c == 'T': b = 3
            else: b = 0
            idx = idx * 4 + b
        counts[idx] += 1
    total = counts.sum()
    if total == 0: return 0
    f = counts / total
    proj = f @ P
    subset = proj[indices] if len(indices) >= 3 else proj[:3]
    return abs(skew(subset)) * 6.07 + 0.10

def random_dna(length, gc=0.5):
    probs = [(1-gc)/2, gc/2, gc/2, (1-gc)/2]
    return ''.join(np.random.choice(['A','C','G','T'], length, p=probs))

def repeat_dna(length, unit='AAAT'):
    return (unit * (length // len(unit) + 1))[:length]

def structured_dna(length, block_size=100):
    """Alternating AT-rich and GC-rich blocks"""
    seq = ''
    for i in range(length // block_size + 1):
        if i % 2 == 0:
            seq += random_dna(block_size, gc=0.3)
        else:
            seq += random_dna(block_size, gc=0.7)
    return seq[:length]

# ============================================================
# EXPERIMENT 1: WHY PRIMES?
# Compare index sets on discriminating structured vs random
# ============================================================
print("=== EXP 1: WHY PRIMES? ===")
np.random.seed(123)
n_trials = 200

index_sets = {
    'primes': PRIMES,
    'non_primes': NON_PRIMES[:95],
    'evens': EVENS,
    'odds': ODDS,
    'random': RANDOM_IDX,
    'consecutive': CONSECUTIVE,
    'all_500': list(range(500)),
}

for name, idxs in index_sets.items():
    random_evs = [compute_ev(random_dna(5000), idxs) for _ in range(n_trials)]
    struct_evs = [compute_ev(structured_dna(5000), idxs) for _ in range(n_trials)]
    repeat_evs = [compute_ev(repeat_dna(5000, 'AAAT'), idxs) for _ in range(n_trials)]
    
    sep = abs(np.mean(struct_evs) - np.mean(random_evs))
    pooled_std = np.sqrt((np.std(random_evs)**2 + np.std(struct_evs)**2) / 2)
    cohens_d = sep / pooled_std if pooled_std > 0 else 0
    
    print(f"  {name:15s}: random={np.mean(random_evs):.3f}±{np.std(random_evs):.3f}, "
          f"struct={np.mean(struct_evs):.3f}±{np.std(struct_evs):.3f}, "
          f"repeat={np.mean(repeat_evs):.3f}, d={cohens_d:.3f}")

# ============================================================
# EXPERIMENT 2: ALPHABET GENERALIZATION
# Does Ev work for ANY symbolic alphabet, not just DNA?
# ============================================================
print("\n=== EXP 2: ALPHABET GENERALIZATION ===")

def compute_ev_generic(sequence, alphabet_size, window=None, indices=PRIMES):
    """Ev for any integer sequence with given alphabet size"""
    if window: sequence = sequence[:window]
    n = len(sequence)
    n_kmers = alphabet_size ** 4
    counts = np.zeros(n_kmers)
    for i in range(n - 3):
        idx = 0
        for j in range(4):
            idx = idx * alphabet_size + sequence[i+j]
        if idx < n_kmers:
            counts[idx] += 1
    total = counts.sum()
    if total == 0: return 0
    f = counts / total
    # Need appropriate projection matrix
    P_gen = RNG.standard_normal((n_kmers, max(500, n_kmers*2))) / np.sqrt(n_kmers)
    proj = f @ P_gen
    valid_idx = [i for i in indices if i < proj.shape[0]]
    if len(valid_idx) < 3: valid_idx = list(range(min(95, proj.shape[0])))
    return abs(skew(proj[valid_idx])) * 6.07 + 0.10

# Binary (alphabet=2): structured vs random
print("  Binary (alphabet=2):")
bin_random = [compute_ev_generic(np.random.randint(0, 2, 5000), 2) for _ in range(100)]
bin_struct = [compute_ev_generic(np.array([i%2 for i in range(5000)]), 2) for _ in range(1)]
print(f"    random={np.mean(bin_random):.3f}±{np.std(bin_random):.3f}, alternating={bin_struct[0]:.3f}")

# Protein (alphabet=20)
print("  Protein (alphabet=20):")
prot_random = [compute_ev_generic(np.random.randint(0, 20, 5000), 20) for _ in range(50)]
prot_repeat = [compute_ev_generic(np.tile(np.arange(20), 250), 20) for _ in range(1)]
print(f"    random={np.mean(prot_random):.3f}±{np.std(prot_random):.3f}, repeat={prot_repeat[0]:.3f}")

# Text (alphabet=26)
print("  Text (alphabet=26):")
text_random = [compute_ev_generic(np.random.randint(0, 26, 5000), 26) for _ in range(50)]
# English-like: high frequency of E,T,A,O,I,N
eng_probs = np.ones(26) * 0.01
for i, freq in zip([4,19,0,14,8,13], [0.13,0.09,0.08,0.08,0.07,0.07]):
    eng_probs[i] = freq
eng_probs /= eng_probs.sum()
text_english = [compute_ev_generic(np.random.choice(26, 5000, p=eng_probs), 26) for _ in range(50)]
print(f"    random={np.mean(text_random):.3f}±{np.std(text_random):.3f}, "
      f"english-like={np.mean(text_english):.3f}±{np.std(text_english):.3f}")

# ============================================================
# EXPERIMENT 3: CONVERGENCE RATE
# How does Ev variance decrease with window size?
# ============================================================
print("\n=== EXP 3: CONVERGENCE RATE ===")
np.random.seed(456)
for window in [500, 1000, 2000, 5000, 10000, 20000, 50000]:
    evs = [compute_ev(random_dna(window)) for _ in range(50)]
    print(f"  w={window:6d}: mean={np.mean(evs):.4f}, std={np.std(evs):.4f}, cv={np.std(evs)/np.mean(evs)*100:.1f}%")

# ============================================================
# EXPERIMENT 4: MATHEMATICAL IDENTITY
# Is Ev related to known information measures?
# ============================================================
print("\n=== EXP 4: EV vs INFORMATION MEASURES ===")
np.random.seed(789)
seqs = []
entropies = []
ev_vals = []
kurtosis_vals = []
gc_vals = []

for gc in np.linspace(0.2, 0.8, 30):
    for _ in range(10):
        seq = random_dna(5000, gc=gc)
        ev = compute_ev(seq)
        
        # Shannon entropy of 4-mer distribution
        counts = np.zeros(256)
        for i in range(len(seq)-3):
            idx = 0
            for j in range(4):
                c = seq[i+j]
                b = 'ACGT'.index(c)
                idx = idx * 4 + b
            counts[idx] += 1
        f = counts / counts.sum()
        H = entropy(f + 1e-10)  # Shannon entropy
        
        # Kurtosis of projection
        proj = f @ P
        kurt = kurtosis(proj[PRIMES])
        
        ev_vals.append(ev)
        entropies.append(H)
        kurtosis_vals.append(kurt)
        gc_vals.append(gc)

r_entropy, p_entropy = spearmanr(ev_vals, entropies)
r_kurtosis, p_kurtosis = spearmanr(ev_vals, kurtosis_vals)
r_gc, p_gc = spearmanr(ev_vals, gc_vals)
print(f"  Ev vs Shannon entropy:     r={r_entropy:.4f}, p={p_entropy:.2e}")
print(f"  Ev vs projection kurtosis: r={r_kurtosis:.4f}, p={p_kurtosis:.2e}")
print(f"  Ev vs GC content:          r={r_gc:.4f}, p={p_gc:.2e}")

# Partial correlation: Ev vs entropy controlling for GC
from numpy.linalg import lstsq
X = np.column_stack([gc_vals, np.ones(len(gc_vals))])
ev_resid = np.array(ev_vals) - X @ lstsq(X, ev_vals, rcond=None)[0]
H_resid = np.array(entropies) - X @ lstsq(X, entropies, rcond=None)[0]
r_partial, p_partial = spearmanr(ev_resid, H_resid)
print(f"  Ev vs entropy (partial|GC): r={r_partial:.4f}, p={p_partial:.2e}")

# ============================================================
# EXPERIMENT 5: SEED UNIVERSALITY
# Does the STRUCTURE of Ev depend on the random seed?
# ============================================================
print("\n=== EXP 5: SEED UNIVERSALITY ===")
test_seqs = [random_dna(5000, gc=gc) for gc in [0.3, 0.4, 0.5, 0.6, 0.7] for _ in range(20)]

seed_results = {}
for seed in [42, 0, 1, 7, 13, 99, 123, 256, 1000, 9999]:
    rng = np.random.default_rng(seed)
    P_seed = rng.standard_normal((256, 500)) / np.sqrt(256)
    primes = PRIMES
    
    evs = []
    for seq in test_seqs:
        counts = np.zeros(256)
        for i in range(len(seq)-3):
            idx = 0
            for j in range(4):
                idx = idx * 4 + 'ACGT'.index(seq[i+j])
            counts[idx] += 1
        f = counts / counts.sum()
        proj = f @ P_seed
        evs.append(abs(skew(proj[primes])) * 6.07 + 0.10)
    seed_results[seed] = evs

# Cross-seed correlations
print("  Seed pair correlations (should be HIGH if structure is universal):")
seeds = list(seed_results.keys())
cors = []
for i in range(len(seeds)):
    for j in range(i+1, len(seeds)):
        r, p = spearmanr(seed_results[seeds[i]], seed_results[seeds[j]])
        cors.append(r)
        if i < 3 and j < 6:
            print(f"    seed {seeds[i]} vs {seeds[j]}: r={r:.4f}")
print(f"  Mean cross-seed r: {np.mean(cors):.4f} ± {np.std(cors):.4f}")
print(f"  Min cross-seed r:  {np.min(cors):.4f}")

# ============================================================
# EXPERIMENT 6: PRIME OPTIMALITY — RIGOROUS TEST
# Sweep ALL possible 95-element subsets... too many.
# Instead: test statistical property of primes vs random subsets
# ============================================================
print("\n=== EXP 6: PRIME OPTIMALITY ===")
np.random.seed(111)
# Generate structured test set
test_random = [random_dna(5000) for _ in range(100)]
test_struct = [structured_dna(5000) for _ in range(100)]

def discrimination_power(indices, test_r, test_s):
    """Cohen's d between structured and random Ev distributions"""
    evr = [compute_ev(s, indices) for s in test_r]
    evs = [compute_ev(s, indices) for s in test_s]
    d = abs(np.mean(evs) - np.mean(evr)) / np.sqrt((np.std(evr)**2 + np.std(evs)**2)/2)
    return d

d_primes = discrimination_power(PRIMES, test_random, test_struct)
print(f"  Primes:      d={d_primes:.4f}")

# 100 random 95-element subsets
d_randoms = []
for trial in range(100):
    rand_idx = sorted(np.random.choice(500, 95, replace=False))
    d = discrimination_power(rand_idx, test_random, test_struct)
    d_randoms.append(d)
print(f"  Random (100): d={np.mean(d_randoms):.4f} ± {np.std(d_randoms):.4f}")
print(f"  Primes percentile: {(sum(d < d_primes for d in d_randoms) / len(d_randoms))*100:.1f}%")

# Specific structured subsets
for name, idxs in [('evens', EVENS), ('odds', ODDS), ('consecutive', CONSECUTIVE)]:
    d = discrimination_power(idxs, test_random, test_struct)
    print(f"  {name:12s}: d={d:.4f}")

print("\n=== SUMMARY ===")
print("If primes >> random: prime selection is mathematically special")
print("If primes ≈ random: any aperiodic subset works equally well")
print("If primes < random: prime selection is actually suboptimal")
