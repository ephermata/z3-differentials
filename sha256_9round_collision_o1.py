import sys

# SHA-256 Bitwise Functions
def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def Sigma0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def Sigma1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

def ch(x, y, z):
    return (x & y) ^ (~x & z)

def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
]

H_INIT = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

def get_W(S8):
    """
    Inverts the first 8 rounds of SHA-256.
    Given an 8-round output state S8, returns the unique W0...W7 that produces it.
    """
    a8, a7, a6, a5, e8, e7, e6, e5 = S8
    
    # Step backwards to recover a4, a3, a2, a1
    a4 = (Sigma0(a7) + maj(a7, a6, a5) - (a8 - e8)) & 0xFFFFFFFF
    a3 = (Sigma0(a6) + maj(a6, a5, a4) - (a7 - e7)) & 0xFFFFFFFF
    a2 = (Sigma0(a5) + maj(a5, a4, a3) - (a6 - e6)) & 0xFFFFFFFF
    a1 = (Sigma0(a4) + maj(a4, a3, a2) - (a5 - e5)) & 0xFFFFFFFF
    
    a0, b0, c0, d0, e0, f0, g0, h0 = H_INIT
    
    a_seq = [a0, a1, a2, a3, a4, a5, a6, a7, a8]
    e_seq = [e0, 0, 0, 0, 0, e5, e6, e7, e8]
    
    # Step forwards to calculate e1, e2, e3, e4
    e_seq[1] = (a1 - ((Sigma0(a0) + maj(a0, b0, c0)) & 0xFFFFFFFF) + d0) & 0xFFFFFFFF
    e_seq[2] = (a2 - ((Sigma0(a1) + maj(a1, a0, b0)) & 0xFFFFFFFF) + c0) & 0xFFFFFFFF
    e_seq[3] = (a3 - ((Sigma0(a2) + maj(a2, a1, a0)) & 0xFFFFFFFF) + b0) & 0xFFFFFFFF
    e_seq[4] = (a4 - ((Sigma0(a3) + maj(a3, a2, a1)) & 0xFFFFFFFF) + a0) & 0xFFFFFFFF
    
    W = []
    # Recover W0...W7
    for t in range(8):
        h_t = H_INIT[7] if t==0 else (H_INIT[6] if t==1 else (H_INIT[5] if t==2 else e_seq[t-3]))
        f_t = H_INIT[5] if t==0 else e_seq[t-1]
        g_t = H_INIT[6] if t==0 else (H_INIT[5] if t==1 else e_seq[t-2])
        e_t = e_seq[t]
        
        T2_t = (Sigma0(a_seq[t]) + maj(a_seq[t], 
                H_INIT[1] if t==0 else a_seq[t-1], 
                H_INIT[2] if t==0 else (H_INIT[1] if t==1 else a_seq[t-2]))) & 0xFFFFFFFF
                
        T1_t = (a_seq[t+1] - T2_t) & 0xFFFFFFFF
        wt = (T1_t - h_t - Sigma1(e_t) - ch(e_t, f_t, g_t) - K[t]) & 0xFFFFFFFF
        W.append(wt)
        
    return W

def generate_9round_collision():
    print("--- O(1) 9-Round SHA-256 Collision Generator ---")
    
    # 1. Pick a random valid 8-round target state S8_1
    import random
    random.seed(42)
    W_orig = [random.randint(0, 0xFFFFFFFF) for _ in range(8)]
    
    def fwd_hash(W):
        a, b, c, d, e, f, g, h = H_INIT
        for i in range(len(W)):
            T1 = (h + Sigma1(e) + ch(e, f, g) + K[i] + W[i]) & 0xFFFFFFFF
            T2 = (Sigma0(a) + maj(a, b, c)) & 0xFFFFFFFF
            h, g, f, e = g, f, e, (d + T1) & 0xFFFFFFFF
            d, c, b, a = c, b, a, (T1 + T2) & 0xFFFFFFFF
        return [a, b, c, d, e, f, g, h]

    S8_1 = fwd_hash(W_orig)
    state_1 = [S8_1[0], S8_1[1], S8_1[2], S8_1[3], S8_1[4], S8_1[5], S8_1[6], S8_1[7]]

    # 2. Create S8_2 that differs ONLY in the final h value (which is e5 historically)
    state_2 = list(state_1)
    diff = 0x12345678
    state_2[7] = (state_2[7] + diff) & 0xFFFFFFFF

    # 3. Invert the 8 rounds to get the exact W0..W7 for both paths
    W1 = get_W(state_1)
    W2 = get_W(state_2)

    # 4. We can set W8_1 arbitrarily. 
    W8_1 = 0x0
    
    # 5. Calculate W8_2 to perfectly absorb the difference in h8
    W8_2 = (W8_1 + state_1[7] - state_2[7]) & 0xFFFFFFFF

    print("\nMessage 1 (W0...W8):")
    print([hex(x) for x in W1 + [W8_1]])
    
    print("\nMessage 2 (W0...W8):")
    print([hex(x) for x in W2 + [W8_2]])

    # Verify
    H9_1 = fwd_hash(W1 + [W8_1])
    H9_2 = fwd_hash(W2 + [W8_2])
    
    print("\nFinal 9-Round State 1:", [hex(x) for x in H9_1])
    print("Final 9-Round State 2:", [hex(x) for x in H9_2])
    
    if H9_1 == H9_2:
        print("\nSUCCESS! PERFECT 9-ROUND COLLISION FOUND IN O(1) TIME.")
    else:
        print("\nFAILED.")

if __name__ == "__main__":
    generate_9round_collision()
