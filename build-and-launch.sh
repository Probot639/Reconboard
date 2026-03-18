#!/usr/bin/env bash

set -euo pipefail

# Prompt for password securely
read -rsp "Enter the reconboard password we will be using: " password
echo
export REDRECON_PASSWORD="$password"

# Prompt for worker count
while true; do
    read -rp "How many workers do you want to launch? " workers
    if [[ "$workers" =~ ^[1-9][0-9]*$ ]]; then
        break
    else
        echo "Please enter a valid positive integer."
    fi
done

echo ""
echo "  Building images..."
docker compose build --no-cache

echo ""
echo "  Launching with $workers worker(s)..."
docker compose up -d --scale worker="$workers"

echo ""
echo "  Done! $workers worker(s) are up."
