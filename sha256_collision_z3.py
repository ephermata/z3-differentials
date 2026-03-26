from z3 import *

def rotr(x, n):
    """Right rotate for 32-bit BitVec."""
    return RotateRight(x, n)

def shr(x, n):
    """Right shift for 32-bit BitVec."""
    return LShR(x, n)

def ch(x, y, z):
    return (x & y) ^ (~x & z)

def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def Sigma0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def Sigma1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

def sigma0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)

def sigma1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)

# SHA-256 Constants
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# Initial Hash Values
H_INIT = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

def sha256_compress_z3(msg_block, rounds=64):
    """
    Models a reduced-round or full SHA-256 compression function in Z3.
    msg_block: List of 16 Z3 BitVec(32) representing the 512-bit message block.
    rounds: Number of rounds to apply (up to 64).
    """
    W = [None] * 64
    for i in range(16):
        W[i] = msg_block[i]
        
    for i in range(16, rounds):
        W[i] = W[i-16] + sigma0(W[i-15]) + W[i-7] + sigma1(W[i-2])

    a, b, c, d, e, f, g, h = [BitVecVal(val, 32) for val in H_INIT]

    for i in range(rounds):
        T1 = h + Sigma1(e) + ch(e, f, g) + BitVecVal(K[i], 32) + W[i]
        T2 = Sigma0(a) + maj(a, b, c)
        
        h = g
        g = f
        f = e
        e = d + T1
        d = c
        c = b
        b = a
        a = T1 + T2

    # Return the state after `rounds`
    return [a, b, c, d, e, f, g, h]

def find_sha256_collision(rounds=4):
    print(f"--- Modeling SHA-256 Collision for {rounds} Rounds ---")
    solver = Solver()

    # Define two distinct message blocks M1 and M2
    M1 = [BitVec(f'M1_{i}', 32) for i in range(16)]
    M2 = [BitVec(f'M2_{i}', 32) for i in range(16)]

    # Constraint: Messages must be different
    solver.add(Or([M1[i] != M2[i] for i in range(16)]))

    # Compute the hashes
    H1 = sha256_compress_z3(M1, rounds)
    H2 = sha256_compress_z3(M2, rounds)

    # Constraint: Hashes must be equal (Collision!)
    for i in range(8):
        solver.add(H1[i] == H2[i])

    print("Solving... (Note: > 20 rounds might take until the heat death of the universe)")
    
    if solver.check() == sat:
        print("Collision Found!")
        model = solver.model()
        
        m1_vals = [hex(model[M1[i]].as_long()) for i in range(16)]
        m2_vals = [hex(model[M2[i]].as_long()) for i in range(16)]
        
        print("\nMessage 1 (Hex Words):")
        print(m1_vals)
        print("\nMessage 2 (Hex Words):")
        print(m2_vals)
    else:
        print("No collision found (or solver timed out).")

if __name__ == "__main__":
    # Test on a highly reduced number of rounds so it actually finishes.
    # Standard SHA-256 is 64 rounds. Z3 will hang indefinitely on 64 rounds.
    find_sha256_collision(rounds=16)
