import sys
import time
from z3 import *
sys.path.append('/home/ec2-user/.openclaw/workspace/z3-differentials')
from sha256_collision_z3 import sha256_compress_z3

def find_collision_with_expansion(rounds, timeout_secs=300):
    """
    Search for SHA-256 collisions for 17+ rounds where the message expansion
    W_16 = sigma1(W_14) + W_9 + sigma0(W_1) + W_0
    becomes active.
    """
    print(f"\n--- Searching for {rounds}-Round SHA-256 Collision ---")
    print(f"Message Expansion Active: {'YES' if rounds > 16 else 'NO'}")
    
    solver = Solver()
    solver.set("timeout", timeout_secs * 1000)

    # 16 Base Message Words
    M1 = [BitVec(f'M1_{i}', 32) for i in range(16)]
    M2 = [BitVec(f'M2_{i}', 32) for i in range(16)]

    # We must have at least one difference to be a true collision
    solver.add(Or([M1[i] != M2[i] for i in range(16)]))

    # DIFFERENTIAL HINT: To prevent Z3 from drowning in the state space, 
    # we force a specific active window. For a Chabaud-Joux style local collision,
    # we can try to restrict the differences to a 9-word window (e.g., W0 to W8).
    # This means W9 to W15 are strictly identical.
    for i in range(9, 16):
        solver.add(M1[i] == M2[i])
        
    # Furthermore, to prevent massive avalanche in the expansion W_16...
    # W_16 = sigma1(W_14) + W_9 + sigma0(W_1) + W_0
    # If W14 and W9 have no difference, Delta W_16 depends entirely on W_0 and W_1.
    # We can ask Z3 to specifically look for a path where Delta W_16 = 0, 
    # or just let it map the probability.

    # Hash
    H1 = sha256_compress_z3(M1, rounds)
    H2 = sha256_compress_z3(M2, rounds)

    # Output State Collision Constraint
    for i in range(8):
        solver.add(H1[i] == H2[i])

    print(f"Solving (Timeout = {timeout_secs}s)...")
    start_t = time.time()
    res = solver.check()
    end_t = time.time()
    
    if res == sat:
        print(f"[{rounds} Rounds] Collision Found in {end_t - start_t:.2f} seconds!")
        m = solver.model()
        print("M1:", [hex(m[M1[i]].as_long()) for i in range(16)])
        print("M2:", [hex(m[M2[i]].as_long()) for i in range(16)])
    elif res == unsat:
        print(f"[{rounds} Rounds] UNSAT - The restricted differential path is impossible.")
    else:
        print(f"[{rounds} Rounds] UNKNOWN - Solver timed out after {end_t - start_t:.2f}s.")
        print("This is expected for 17+ rounds without strict probability trails!")

if __name__ == "__main__":
    # Test 17 rounds
    find_collision_with_expansion(17, timeout_secs=120)
    # Test 18 rounds
    find_collision_with_expansion(18, timeout_secs=120)
