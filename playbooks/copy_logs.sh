#!/bin/bash

# Check for two arguments
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <base_destination_path> <subfolder>"
    echo "Example: $0 /usr/local/dos-mitigation/logs/test_name UB"
    exit 1
fi

# Array of remote sources in the format: user@host:/path/to/source
REMOTE_HOSTS=(
    "a0"
    "s0"
    "c0"
    "auth0"
    "sink0"
)
REMOTE_USER="ubansal"
REMOTE_DIR="/tmp/logs.zip"

# Destination
DEST_USER="ubansal"
DEST_HOST="control0"
BASE_DEST_DIR="$1"
SUBFOLDER="$2"
DEST_DIR="$BASE_DEST_DIR/$SUBFOLDER"

# Loop through each remote source and copy files
for HOST in "${REMOTE_HOSTS[@]}"; do

    echo "Checking if source path exists on $HOST..."

    ssh "$REMOTE_USER@$HOST" "[ -d '$REMOTE_DIR' ]"
    if [ $? -ne 0 ]; then
        echo "WARNING: Source path '$REMOTE_DIR' does not exist on $HOST. Skipping."
        continue
    fi

    echo "Starting copy from $REMOTE_USER@$HOST:$REMOTE_DIR to $DEST_USER@$DEST_HOST:$DEST_DIR/$HOST/logs.zip"
    
    # Use ssh to run scp from the source to the destination
    ssh "$REMOTE_USER@$HOST" "scp -r $REMOTE_DIR/* $DEST_USER@$DEST_HOST:$DEST_DIR/$HOST/logs.zip"

    echo "Finished copying from $HOST"
done

echo "All transfers complete."

