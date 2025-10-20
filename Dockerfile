# Web Crawler Docker Image
FROM ubuntu:22.04

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DEBIAN_FRONTEND=noninteractive

# Install Python 3.10 (default in Ubuntu 22.04) and system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    chromium-browser \
    chromium-chromedriver \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Create symlinks for python and pip
RUN ln -s /usr/bin/python3 /usr/bin/python

# Create app directory
WORKDIR /opt/crawler/app

# Create necessary directories with proper permissions
RUN mkdir -p /opt/crawler/archives /opt/crawler/db /opt/crawler/temp /opt/crawler/config && \
    chmod 755 /opt/crawler/archives && \
    chmod 755 /opt/crawler/db && \
    chmod 755 /opt/crawler/temp && \
    chmod 755 /opt/crawler/config

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
