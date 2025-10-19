# Web Crawler Docker Image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    chromium \
    chromium-driver \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /opt/crawler/app

# Create necessary directories
RUN mkdir -p /opt/crawler/{archives,db,temp,config}

# Copy requirements.txt
COPY requirements.txt /opt/crawler/app/

# Install Python dependencies
RUN pip install --no-cache-dir -r /opt/crawler/app/requirements.txt

# Copy application files
COPY crawler.py /opt/crawler/app/
COPY runner.py /opt/crawler/app/
COPY templates/ /opt/crawler/app/templates/
COPY crawler.cfg /opt/crawler/config/
COPY default_ignores.tsv /opt/crawler/config/
COPY docker_startup.sh /opt/crawler/app/

# Make startup script executable
RUN chmod +x /opt/crawler/app/docker_startup.sh

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/ || exit 1

# Start command
CMD ["/opt/crawler/app/docker_startup.sh"]
