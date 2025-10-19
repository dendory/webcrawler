#!/bin/bash
# This script builds the Docker image and pushes it to Docker Hub

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

# Configuration
DOCKER_USERNAME="dendory02"
IMAGE_NAME="webcrawler"

# Read version from VERSION file
if [ -f "VERSION" ]; then
    VERSION=$(cat VERSION | tr -d '\n\r')
else
    print_error "VERSION file not found!"
    exit 1
fi

TAG="latest"
FULL_IMAGE_NAME="${DOCKER_USERNAME}/${IMAGE_NAME}:${TAG}"
VERSIONED_IMAGE_NAME="${DOCKER_USERNAME}/${IMAGE_NAME}:${VERSION}"

print_status "Starting Docker build and push process..."
print_status "Version: ${VERSION}"
print_status "Latest image: ${FULL_IMAGE_NAME}"
print_status "Versioned image: ${VERSIONED_IMAGE_NAME}"

# Check if Docker is installed and running
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi

if ! docker info &> /dev/null; then
    print_error "Docker is not running. Please start Docker first."
    exit 1
fi

# Check if user is logged in to Docker Hub
print_status "Checking Docker Hub authentication..."
if ! docker info | grep -q "Username: ${DOCKER_USERNAME}"; then
    print_warning "Not logged in to Docker Hub as ${DOCKER_USERNAME}"
fi

# Build the Docker image
print_status "Building Docker image..."
docker build -t "${FULL_IMAGE_NAME}" -t "${VERSIONED_IMAGE_NAME}" .

if [ $? -eq 0 ]; then
    print_success "Docker image built successfully!"
else
    print_error "Docker build failed!"
    exit 1
fi

# Push the images to Docker Hub
print_status "Pushing images to Docker Hub..."
print_status "Pushing latest tag..."
docker push "${FULL_IMAGE_NAME}"

if [ $? -eq 0 ]; then
    print_success "Latest image pushed successfully!"
else
    print_error "Failed to push latest image to Docker Hub!"
    exit 1
fi

print_status "Pushing versioned tag..."
docker push "${VERSIONED_IMAGE_NAME}"

if [ $? -eq 0 ]; then
    print_success "Versioned image pushed successfully!"
else
    print_error "Failed to push versioned image to Docker Hub!"
    exit 1
fi

# Display usage information
print_success "Build and push completed successfully!"
