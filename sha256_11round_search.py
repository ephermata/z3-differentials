import sys
from z3 import *
sys.path.append('/home/ec2-user/.openclaw/workspace/z3-differentials')
from sha256_collision_z3 import sha256_compress_z3
import time

def find_collision(rounds, timeout_secs=120):
    print(f"\n--- Searching for {rounds}-Round SHA-256 Collision ---")
    solver = Solver()
    solver.set("timeout", timeout_secs * 1000)

    M1 = [BitVec(f'M1_{i}', 32) for i in range(16)]
    M2 = [BitVec(f'M2_{i}', 32) for i in range(16)]

    # Structural Hint: Restrict the difference to only the active message words.
    # Words beyond the round count are identical.
    for i in range(rounds, 16):
        solver.add(M1[i] == M2[i])
        
    # Restrict differences to be low-Hamming-weight or only in specific words 
    # to drastically reduce the Z3 search space.
    # For a classic local collision, the difference starts in W0 and is absorbed by W_8.
    # If rounds > 9, we might let the difference start in W1 or W2.
    diff_start = 0
    solver.add(M1[diff_start] != M2[diff_start])
    
    # Require no difference in the message expansion *before* the start word
    for i in range(diff_start):
        solver.add(M1[i] == M2[i])

    # Hash
    H1 = sha256_compress_z3(M1, rounds)
    H2 = sha256_compress_z3(M2, rounds)

    # Collision Constraint
    for i in range(8):
        solver.add(H1[i] == H2[i])

    print(f"Solving (Timeout = {timeout_secs}s)...")
    start_t = time.time()
    res = solver.check()
    end_t = time.time()
    
    if res == sat:
        print(f"[{rounds} Rounds] Collision Found in {end_t - start_t:.2f} seconds!")
        m = solver.model()
        print("M1:", [hex(m[M1[i]].as_long()) for i in range(rounds)])
        print("M2:", [hex(m[M2[i]].as_long()) for i in range(rounds)])
    elif res == unsat:
        print(f"[{rounds} Rounds] UNSAT - Contradiction reached.")
    else:
        print(f"[{rounds} Rounds] UNKNOWN - Solver timed out or gave up after {end_t - start_t:.2f}s.")

if __name__ == "__main__":
    find_collision(10, timeout_secs=60)
    find_collision(11, timeout_secs=60)
