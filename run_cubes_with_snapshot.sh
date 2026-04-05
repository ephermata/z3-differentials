#!/bin/bash
CUBES_DIR=$1
KISSAT_BIN="/home/ec2-user/.openclaw/workspace/z3-differentials/kissat/build/kissat"

if [ -z "$CUBES_DIR" ]; then
    echo "Usage: $0 <cubes_dir>"
    exit 1
fi

mkdir -p results_17

for cube in $CUBES_DIR/*.cnf; do
    filename=$(basename -- "$cube")
    result_file="results_17/${filename}.out"
    
    if [ -f "$result_file" ]; then
        echo "Skipping $cube (already processed)"
        continue
    fi
    
    echo "Starting $cube..."
    $KISSAT_BIN --relaxed $cube > $result_file &
    KISSAT_PID=$!
    
    # Start snapshot script in background (runs every hour)
    ./snapshot_kissat.sh start $KISSAT_PID > "snapshot_${filename}.log" 2>&1 &
    SNAP_PID=$!
    
    # Wait for Kissat to finish this cube
    wait $KISSAT_PID
    EXIT_CODE=$?
    
    # Stop the snapshot loop for this PID once it finishes
    kill $SNAP_PID 2>/dev/null
    
    # Exit code 10 means SATISFIABLE in Kissat/SAT solvers
    if [ $EXIT_CODE -eq 10 ]; then
        echo "SATISFIABLE result found in $cube!"
        echo "SAT found in $cube" > results_17/FINAL_RESULT.txt
        exit 0
    fi
done

echo "All cubes processed."
