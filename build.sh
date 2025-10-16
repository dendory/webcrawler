#!/bin/bash

# Build script for Web Crawler Docker image
# This script builds the image and pushes it to Docker Hub

set -e  # Exit on any error

# Configuration
IMAGE_NAME="webcrawler"
VERSION="0.1.3"
DOCKER_HUB_USERNAME="${DOCKER_HUB_USERNAME:-dendory02}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Building Web Crawler Docker Image${NC}"
echo "=================================="

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running. Please start Docker and try again.${NC}"
    exit 1
fi

# Check if logged into Docker Hub
if ! docker info | grep -q "Username:"; then
    echo -e "${YELLOW}Warning: Not logged into Docker Hub. You may need to run 'docker login' first.${NC}"
fi

# Build the image
echo -e "${GREEN}Building image: ${IMAGE_NAME}:${VERSION}${NC}"
docker build -t "${IMAGE_NAME}:${VERSION}" .

# Also tag as latest
echo -e "${GREEN}Tagging as latest${NC}"
docker tag "${IMAGE_NAME}:${VERSION}" "${IMAGE_NAME}:latest"

# Tag for Docker Hub
echo -e "${GREEN}Tagging for Docker Hub${NC}"
docker tag "${IMAGE_NAME}:${VERSION}" "${DOCKER_HUB_USERNAME}/${IMAGE_NAME}:${VERSION}"
docker tag "${IMAGE_NAME}:latest" "${DOCKER_HUB_USERNAME}/${IMAGE_NAME}:latest"

# Push to Docker Hub
echo -e "${GREEN}Pushing to Docker Hub${NC}"
docker push "${DOCKER_HUB_USERNAME}/${IMAGE_NAME}:${VERSION}"
docker push "${DOCKER_HUB_USERNAME}/${IMAGE_NAME}:latest"

echo -e "${GREEN}Build and push completed successfully!${NC}"
echo ""
echo "Images created:"
echo "  - ${IMAGE_NAME}:${VERSION}"
echo "  - ${IMAGE_NAME}:latest"
echo "  - ${DOCKER_HUB_USERNAME}/${IMAGE_NAME}:${VERSION}"
echo "  - ${DOCKER_HUB_USERNAME}/${IMAGE_NAME}:latest"
echo ""
echo "To run the container:"
echo "  docker run -d --name webcrawler -p 8080:8080 -v /path/to/data:/data ${DOCKER_HUB_USERNAME}/${IMAGE_NAME}:latest"
echo ""
echo "To test locally:"
echo "  docker run -d --name webcrawler -p 8080:8080 -v \$(pwd)/data:/data ${IMAGE_NAME}:latest"
