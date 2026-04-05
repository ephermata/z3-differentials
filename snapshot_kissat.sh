#!/bin/bash
# Checkpoint and Restore script using CRIU (Checkpoint/Restore In Userspace)
# Usage: 
#   ./snapshot_kissat.sh start <pid>      - Starts taking snapshots every 1 hour
#   ./snapshot_kissat.sh restore <dir>    - Restores a process from a snapshot directory

CMD=$1
TARGET_PID=$2
INTERVAL_SEC=3600 # 1 hour

if [ "$CMD" == "start" ]; then
    if [ -z "$TARGET_PID" ]; then
        echo "Usage: $0 start <pid>"
        exit 1
    fi
    echo "Starting periodic snapshots for PID $TARGET_PID every $INTERVAL_SEC seconds..."
    
    while true; do
        sleep $INTERVAL_SEC
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        DUMP_DIR="checkpoint_${TARGET_PID}_${TIMESTAMP}"
        mkdir -p $DUMP_DIR
        
        echo "[$(date)] Creating snapshot of PID $TARGET_PID in $DUMP_DIR..."
        # We use sudo because criu requires root access to freeze and dump memory
        sudo criu dump -t $TARGET_PID --images-dir $DUMP_DIR --leave-running --shell-job
        
        if [ $? -eq 0 ]; then
            echo "[$(date)] Snapshot successful."
            # Optionally delete older snapshots here to save disk space
        else
            echo "[$(date)] Snapshot failed."
        fi
    done

elif [ "$CMD" == "restore" ]; then
    DUMP_DIR=$2
    if [ -z "$DUMP_DIR" ]; then
        echo "Usage: $0 restore <dump_directory>"
        exit 1
    fi
    echo "Restoring process from $DUMP_DIR..."
    sudo criu restore --images-dir $DUMP_DIR --shell-job
else
    echo "Unknown command: $CMD"
    echo "Usage:"
    echo "  $0 start <pid>"
    echo "  $0 restore <dump_directory>"
fi