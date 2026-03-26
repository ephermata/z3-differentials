import sys
import time
from z3 import *

def rotr(x, n):
    return RotateRight(x, n)

def Sigma0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def Sigma1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

def ch(x, y, z):
    return (x & y) ^ (~x & z)

def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def popcount_z3(x):
    """Z3 macro to count the number of 1s (active bits) in a BitVec."""
    return Sum([ZeroExt(31, Extract(i, i, x)) for i in range(32)])

# SHA-256 Constants
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
]

H_INIT = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

def search_optimal_trail(rounds=5, timeout_secs=120):
    print(f"\n--- Z3 Optimal ARX Differential Trail Searcher ({rounds} Rounds) ---")
    
    # Use Optimize() to find the mathematically highest probability trail
    opt = Optimize()
    opt.set("timeout", timeout_secs * 1000)
    
    M1 = [BitVec(f'M1_{i}', 32) for i in range(16)]
    M2 = [BitVec(f'M2_{i}', 32) for i in range(16)]
    
    # Must have a difference
    opt.add(Or([M1[i] != M2[i] for i in range(16)]))
    
    # Restrict window to speed up search (classic local collision setup)
    for i in range(rounds, 16):
        opt.add(M1[i] == M2[i])
        
    a1, b1, c1, d1, e1, f1, g1, h1 = [BitVecVal(v, 32) for v in H_INIT]
    a2, b2, c2, d2, e2, f2, g2, h2 = [BitVecVal(v, 32) for v in H_INIT]
    
    total_weight = 0
    state_diffs = []
    
    for i in range(rounds):
        T1_1 = h1 + Sigma1(e1) + ch(e1, f1, g1) + BitVecVal(K[i], 32) + M1[i]
        T2_1 = Sigma0(a1) + maj(a1, b1, c1)
        
        T1_2 = h2 + Sigma1(e2) + ch(e2, f2, g2) + BitVecVal(K[i], 32) + M2[i]
        T2_2 = Sigma0(a2) + maj(a2, b2, c2)
        
        h1, g1, f1, e1 = g1, f1, e1, d1 + T1_1
        d1, c1, b1, a1 = c1, b1, a1, T1_1 + T2_1
        
        h2, g2, f2, e2 = g2, f2, e2, d2 + T1_2
        d2, c2, b2, a2 = c2, b2, a2, T1_2 + T2_2
        
        # Track the active bits in the primary diffusion registers
        da = a1 ^ a2
        de = e1 ^ e2
        
        total_weight += popcount_z3(da)
        total_weight += popcount_z3(de)
        total_weight += popcount_z3(M1[i] ^ M2[i]) # Penalize dense message diffs
        
        state_diffs.append((da, de, M1[i] ^ M2[i]))
        
    # Objective: Minimize the total active bits across the entire state path!
    # This directly equates to maximizing the ARX differential probability.
    opt.minimize(total_weight)
    
    # Enforce Collision at the end
    opt.add(a1 == a2, b1 == b2, c1 == c2, d1 == d2)
    opt.add(e1 == e2, f1 == f2, g1 == g2, h1 == h2)
    
    print("Starting Branch-and-Bound Trail Optimization...")
    start = time.time()
    res = opt.check()
    end = time.time()
    
    if res == sat:
        m = opt.model()
        print(f"Optimal Trail Found in {end-start:.2f} seconds!")
        
        weight_val = m.evaluate(total_weight).as_long()
        print(f"Total Trail Weight (Active Bits): {weight_val}")
        print("\nProbability Trail:")
        print("Round | Msg Diff (\u0394W) | \u0394A Register | \u0394E Register")
        print("-" * 55)
        
        for i in range(rounds):
            da, de, dw = state_diffs[i]
            val_a = m.evaluate(da).as_long()
            val_e = m.evaluate(de).as_long()
            val_w = m.evaluate(dw).as_long()
            
            # Format nicely
            hex_a = f"0x{val_a:08x}"
            hex_e = f"0x{val_e:08x}"
            hex_w = f"0x{val_w:08x}"
            print(f" {i:2d}   |  {hex_w}  | {hex_a} | {hex_e}")
            
    else:
        print(f"Solver returned {res} after {end-start:.2f}s.")

if __name__ == "__main__":
    search_optimal_trail(rounds=5, timeout_secs=120)
