# Use Python 3.11 slim image as base
FROM python:3.11-slim

# Set metadata
LABEL maintainer="Patrick Lambert [patrick@dendory.ca]"
LABEL version="0.1.2"
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
RUN chmod +x runner.py

# Create a non-root user
RUN useradd -m -u 1000 crawler && \
    chown -R crawler:crawler /app /data

# Switch to non-root user
USER crawler

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/ || exit 1

# Create startup script
RUN echo '#!/bin/bash\n\
# Start the main application\n\
python crawler.py &\n\
\n\
# Start the runner script on a schedule (every 5 minutes)\n\
while true; do\n\
    python runner.py\n\
    sleep 300\n\
done' > /app/start.sh && chmod +x /app/start.sh

# Set the startup script as entrypoint
CMD ["/app/start.sh"]
