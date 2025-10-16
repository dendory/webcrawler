# Use Python 3.11 slim image as base
FROM python:3.11-slim

# Set metadata
ARG VERSION
LABEL maintainer="Patrick Lambert [patrick@dendory.ca]"
LABEL version="${VERSION}"
LABEL description="This is a modern self-hosted web crawler application that creates WARC archives from web sites."

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV FLASK_HOST=0.0.0.0
ENV FLASK_PORT=8080

# Create app directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    findutils \
    cron \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create data directories
RUN mkdir -p /data/db /data/temp /data/archives

# Set permissions
RUN chmod +x runner.py runner_wrapper.sh

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/ || exit 1

# Create crontab entry for runner script (every 5 minutes)
RUN echo "*/5 * * * * /app/runner_wrapper.sh" | crontab -

# Create startup script
RUN echo '#!/bin/bash\n\
# Start cron daemon\n\
service cron start\n\
\n\
# Start the main application\n\
python crawler.py' > /app/start.sh && chmod +x /app/start.sh

# Set the startup script as entrypoint
CMD ["/app/start.sh"]
