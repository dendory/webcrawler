#!/bin/bash
# Wrapper script for runner.py that ensures database is ready

# Wait for the database to be initialized
while [ ! -f /data/db/crawler.db ] || [ ! -s /data/db/crawler.db ]; do
    echo "Waiting for database to be initialized..."
    sleep 10
done

# Run the actual runner script
cd /app
python runner.py
