#!/bin/bash
# This script removes the web crawler application from a Linux host

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

print_status "Starting Web Crawler uninstallation..."

# Stop and disable the service
print_status "Stopping crawler service..."
if systemctl is-active --quiet crawler.service; then
    systemctl stop crawler.service
    print_success "Service stopped"
else
    print_warning "Service was not running"
fi

print_status "Disabling crawler service..."
systemctl disable crawler.service

# Remove systemd service file
print_status "Removing systemd service file..."
if [ -f /etc/systemd/system/crawler.service ]; then
    rm /etc/systemd/system/crawler.service
    print_success "Service file removed"
else
    print_warning "Service file not found"
fi

# Remove crontab entry
print_status "Removing crontab entry..."
crontab -l 2>/dev/null | grep -v "runner.py" | crontab - 2>/dev/null || true
print_success "Crontab entry removed"

# Reload systemd
print_status "Reloading systemd..."
systemctl daemon-reload

# Ask about removing data
echo ""
print_warning "Do you want to remove all crawler data (archives, database, logs)?"
print_warning "This will permanently delete all crawled archives and configuration."
read -p "Type 'yes' to confirm data removal, or 'no' to keep data: " -r
echo ""

if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    print_status "Removing all crawler data..."
    rm -rf /opt/crawler
    print_success "All crawler data removed"
else
    print_status "Keeping crawler data at /opt/crawler"
    print_warning "You can manually remove /opt/crawler later if needed"
fi

# Remove log files
print_status "Removing log files..."
rm -f /var/log/crawler.log
rm -f /var/log/runner.log
print_success "Log files removed"

print_success "Uninstallation completed successfully!"
echo ""
echo "=== Uninstallation Summary ==="
echo "✓ Service stopped and disabled"
echo "✓ Systemd service file removed"
echo "✓ Crontab entry removed"
echo "✓ Log files removed"
if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    echo "✓ All crawler data removed"
else
    echo "⚠ Crawler data preserved at /opt/crawler"
fi
echo ""
print_success "Web Crawler has been completely removed from the system."
