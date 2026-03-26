from z3 import *

# PRESENT 4-bit S-box
SBOX = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]

# Precompute DDT (Differential Distribution Table)
def compute_ddt():
    ddt = [[0]*16 for _ in range(16)]
    for dx in range(16):
        for x in range(16):
            dy = SBOX[x] ^ SBOX[x ^ dx]
            ddt[dx][dy] += 1
    return ddt

DDT = compute_ddt()

def sbox_constraint(dx, dy, active_var):
    """
    Returns a Z3 constraint representing valid transitions through the S-box.
    dx, dy are 4-bit Z3 BitVec variables.
    active_var is a Z3 Int (0 or 1) indicating if the S-box is active.
    """
    valid_transitions = []
    
    # 0 -> 0 transition (inactive S-box)
    valid_transitions.append(And(dx == 0, dy == 0, active_var == 0))
    
    # Active transitions
    for i in range(1, 16):
        for j in range(1, 16):
            if DDT[i][j] > 0:
                valid_transitions.append(And(dx == i, dy == j, active_var == 1))
                
    return Or(valid_transitions)

def optimize_differentials(rounds=3, num_solutions=3, max_active_sboxes=None):
    print(f"--- Searching for {rounds}-Round Differentials ---")
    
    # 1. Use Optimize() instead of Solver() to find the highest probability (lowest weight)
    opt = Optimize()
    
    # Variables for state differences at each round (4 S-boxes per round = 16 bits)
    state_diffs = [[BitVec(f'dx_r{r}_s{s}', 4) for s in range(4)] for r in range(rounds + 1)]
    
    # Variables for active S-boxes (dummy variables for optimization)
    active_sboxes = [[Int(f'active_r{r}_s{s}') for s in range(4)] for r in range(rounds)]
    
    # Constraints for each round
    for r in range(rounds):
        for s in range(4):
            dx = state_diffs[r][s]
            dy = state_diffs[r+1][s]  # Simplified permutation layer for toy example
            active = active_sboxes[r][s]
            
            # Add S-box constraints
            opt.add(sbox_constraint(dx, dy, active))

    # Total active S-boxes across all rounds (Proxy for weight/probability)
    total_active = Int('total_active')
    opt.add(total_active == Sum([active for r in range(rounds) for active in active_sboxes[r]]))
    
    # Objective: Minimize total active S-boxes
    opt.minimize(total_active)
    
    # Constraint: Must have at least one active S-box at the start (Non-zero input difference)
    opt.add(Sum([state_diffs[0][s] for s in range(4)]) != 0)
    
    # Bounding Strategy (Pruning the search space)
    if max_active_sboxes is not None:
        opt.add(total_active <= max_active_sboxes)

    # Solve and extract multiple optimal differentials
    found = 0
    while opt.check() == sat and found < num_solutions:
        model = opt.model()
        
        weight = model[total_active].as_long()
        print(f"\nSolution {found+1} (Weight / Active S-boxes: {weight}):")
        
        # Build blocking clause to find *additional* distinct inputs/outputs
        blocking_clause = []
        
        for r in range(rounds + 1):
            r_vals = [model[state_diffs[r][s]].as_long() for s in range(4)]
            print(f"  Round {r} State Diff: {['0x%X' % v for v in r_vals]}")
            
            if r == 0 or r == rounds:
                # Require either input diff or output diff to be different next time
                blocking_clause.extend([state_diffs[r][s] != r_vals[s] for s in range(4)])
                
        # Add the symmetry breaking blocking clause
        opt.add(Or(blocking_clause))
        found += 1

if __name__ == "__main__":
    optimize_differentials(rounds=2, num_solutions=5, max_active_sboxes=5)
