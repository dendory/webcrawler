#!/bin/bash
# Startup script for runner

set -e  # Exit on any error

echo "Starting crawler.py..."
python /opt/crawler/app/crawler.py --config /opt/crawler/config/crawler.cfg &

# Function to run runner.py
run_runner() {
    python /opt/crawler/app/runner.py --config /opt/crawler/config/crawler.cfg
}

# Set up a loop to run runner.py every 5 minutes
echo "Setting up runner.py to run every 5 minutes..."
while true; do
    sleep 300  # Wait 5 minutes (300 seconds)
    run_runner
done
