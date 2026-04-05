#!/usr/bin/env python3
import sys
import os
import itertools
import subprocess

def create_cubes(cnf_path, output_dir, num_vars_to_split=10):
    os.makedirs(output_dir, exist_ok=True)
    
    with open(cnf_path, 'r') as f:
        lines = f.readlines()
    
    # Find the variables we want to split on. We'll just pick the first `num_vars_to_split` variables 
    # that appear in the CNF (or you can manually specify a list of target variables).
    # For this example, we split on variables 1 to num_vars_to_split.
    vars_to_split = list(range(1, num_vars_to_split + 1))
    
    # Generate all 2^k true/false combinations
    combinations = list(itertools.product([True, False], repeat=num_vars_to_split))
    print(f"Generating {len(combinations)} cubes...")

    for i, combo in enumerate(combinations):
        cube_lines = list(lines)
        
        # Append unit clauses for this cube
        for var, is_true in zip(vars_to_split, combo):
            lit = str(var) if is_true else f"-{var}"
            cube_lines.append(f"{lit} 0\n")
            
        # Update the header to reflect the new number of clauses
        for j, line in enumerate(cube_lines):
            if line.startswith("p cnf"):
                parts = line.split()
                num_vars = int(parts[2])
                num_clauses = int(parts[3])
                cube_lines[j] = f"p cnf {num_vars} {num_clauses + num_vars_to_split}\n"
                break
                
        cube_path = os.path.join(output_dir, f"cube_{i}.cnf")
        with open(cube_path, 'w') as f:
            f.writelines(cube_lines)
            
    print(f"Done! {len(combinations)} CNF files written to {output_dir}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 cube_and_conquer.py <original.cnf> <output_dir> [num_vars_to_split]")
        sys.exit(1)
        
    cnf_file = sys.argv[1]
    out_dir = sys.argv[2]
    split_vars = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    
    create_cubes(cnf_file, out_dir, split_vars)