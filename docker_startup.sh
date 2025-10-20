#!/bin/bash
# Startup script for runner

set -e  # Exit on any error

echo "Setting up directories and permissions..."

# Ensure database directory exists and has proper permissions
mkdir -p /opt/crawler/db
chmod 755 /opt/crawler/db

# Ensure other directories exist
mkdir -p /opt/crawler/archives
mkdir -p /opt/crawler/temp
chmod 755 /opt/crawler/archives
chmod 755 /opt/crawler/temp

# Verify directories exist and show permissions
echo "Directory setup complete:"
ls -la /opt/crawler/

echo "Starting crawler.py..."
python /opt/crawler/app/crawler.py --config /opt/crawler/config/crawler.cfg &
CRAWLER_PID=$!

# Give crawler a moment to initialize
sleep 5

# Function to run runner.py
run_runner() {
    echo "Running runner.py..."
    python /opt/crawler/app/runner.py --config /opt/crawler/config/crawler.cfg
}

# Run runner.py immediately once
echo "Running initial runner.py..."
run_runner

# Set up a loop to run runner.py every 5 minutes
echo "Setting up runner.py to run every 5 minutes..."
while true; do
    sleep 300  # Wait 5 minutes (300 seconds)
    run_runner
done
