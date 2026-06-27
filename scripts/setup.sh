#!/bin/bash
# ThreatLens — Quick Setup Script
set -e

echo "======================================"
echo "  ThreatLens — Security Platform"
echo "  AUTHORIZED USE ONLY"
echo "======================================"
echo ""
echo "WARNING: This tool is for authorized security testing ONLY."
echo "Ensure you have written permission before scanning any target."
echo ""

# Generate secret key
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(64))")
echo "SECRET_KEY=$SECRET_KEY" > .env
echo "DEBUG=false" >> .env
echo ""
echo "Generated .env with SECRET_KEY"

# Build and start
echo "Building Docker images..."
docker-compose build --no-cache

echo "Starting services..."
docker-compose up -d db redis

echo "Waiting for database..."
sleep 8

echo "Running migrations..."
docker-compose run --rm migrations

echo "Starting remaining services..."
docker-compose up -d

echo ""
echo "======================================"
echo "  ThreatLens is running!"
echo ""
echo "  Frontend:  http://localhost:3000"
echo "  API:       http://localhost:8000/api/docs"
echo "  Flower:    http://localhost:5555"
echo "======================================"
echo ""
echo "Create your first user via the API:"
echo "  curl -X POST http://localhost:8000/api/v1/auth/register \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"email\":\"admin@example.com\",\"username\":\"admin\",\"password\":\"changeme123\"}'"
