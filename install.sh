#!/bin/bash
# This script installs the web crawler application on a Linux host

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root."
   exit 1
fi

print_status "Starting Web Crawler installation..."

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed. Please install Python 3 first."
    exit 1
fi

# Check if pip3 is installed
if ! command -v pip3 &> /dev/null; then
    print_error "pip3 is not installed. Please install pip3 first."
    exit 1
fi

# Create directory structure
print_status "Creating directory structure..."
mkdir -p /opt/crawler/{app,config,archives,db,temp,venv}
mkdir -p /var/log

# Copy application files
print_status "Copying application files..."
cp requirements.txt /opt/crawler/app/
cp crawler.py /opt/crawler/app/
cp runner.py /opt/crawler/app/
cp -r templates /opt/crawler/app/
cp crawler.cfg /opt/crawler/config/
cp default_ignores.tsv /opt/crawler/config/
cp crawler.service /etc/systemd/system/

# Set proper permissions
print_status "Setting file permissions..."
chmod +x /opt/crawler/app/crawler.py
chmod +x /opt/crawler/app/runner.py
chmod 644 /opt/crawler/config/crawler.cfg
chmod 644 /opt/crawler/config/default_ignores.tsv
chmod 644 /etc/systemd/system/crawler.service

# Create virtual environment and install dependencies
print_status "Creating Python virtual environment..."
cd /opt/crawler
python3 -m venv venv
source venv/bin/activate

print_status "Installing Python dependencies..."
pip install --upgrade pip
pip install -r app/requirements.txt

# Install Chrome/Chromium for Selenium (optional but recommended)
print_status "Installing Chrome/Chromium for advanced crawling..."
if command -v apt-get &> /dev/null; then
    # Ubuntu/Debian
    apt-get update
    apt-get install -y chromium
elif command -v yum &> /dev/null; then
    # CentOS/RHEL
    yum install -y chromium chromium-driver
elif command -v dnf &> /dev/null; then
    # Fedora
    dnf install -y chromium chromium-driver
else
    print_warning "Could not install Chrome/Chromium automatically. Please install manually for advanced crawling features."
fi

# Create database directory and set permissions
print_status "Setting up database..."
touch /opt/crawler/db/crawler.db
chmod 664 /opt/crawler/db/crawler.db

# Set ownership
print_status "Setting file ownership..."
chown -R root:root /opt/crawler
chown -R root:root /etc/systemd/system/crawler.service

# Reload systemd and enable service
print_status "Enabling and starting systemd service..."
systemctl daemon-reload
systemctl enable crawler.service

# Setup crontab for runner
print_status "Setting up crontab for crawler runner..."
# Create a temporary crontab file
cat > /tmp/crawler_cron << EOF
# Web Crawler Mapper - runs every 5 minutes
*/5 * * * * /opt/crawler/venv/bin/python /opt/crawler/app/runner.py --config /opt/crawler/config/crawler.cfg >> /var/log/runner.log 2>&1
EOF

# Add to root's crontab
crontab /tmp/crawler_cron
rm /tmp/crawler_cron

# Start the service
print_status "Starting crawler service..."
systemctl restart crawler.service

# Wait a moment for service to start
sleep 3

# Check if service is running
if systemctl is-active --quiet crawler.service; then
    print_success "Crawler service is running successfully!"
else
    print_error "Crawler service failed to start. Check logs with: journalctl -u crawler.service"
    exit 1
fi

# Display status information
print_success "Installation completed successfully! The web interface should be available at: http://localhost:8080"
