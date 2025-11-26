#!/bin/bash

# Production Deployment Script for Daifend Vulnerability Scanner
# This script helps deploy the application to production

set -e

echo "🚀 Starting production deployment..."

# Check if .env file exists
if [ ! -f .env ]; then
    echo "❌ Error: .env file not found!"
    echo "Please create a .env file with all required environment variables."
    echo "See PRODUCTION_DEPLOYMENT.md for details."
    exit 1
fi

# Check if DATABASE_URL is set
if ! grep -q "DATABASE_URL=" .env || grep -q "^DATABASE_URL=$" .env; then
    echo "⚠️  Warning: DATABASE_URL not set in .env"
    echo "The application will use SQLite if DATABASE_URL is not set."
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check if JWT_SECRET_KEY is set
if ! grep -q "JWT_SECRET_KEY=" .env || grep -q "^JWT_SECRET_KEY=$" .env; then
    echo "❌ Error: JWT_SECRET_KEY not set in .env"
    echo "Generate one with: python3 -c \"import secrets; print(secrets.token_urlsafe(32))\""
    exit 1
fi

echo "✅ Environment variables check passed"

# Build and deploy
echo "📦 Building Docker images..."
docker-compose build

echo "🔄 Starting services..."
docker-compose up -d

echo "⏳ Waiting for services to start..."
sleep 5

# Check if services are running
if docker-compose ps | grep -q "Up"; then
    echo "✅ Services are running!"
    echo ""
    echo "📊 Service Status:"
    docker-compose ps
    echo ""
    echo "📝 View logs with: docker-compose logs -f"
    echo "🛑 Stop services with: docker-compose down"
    echo ""
    echo "🌐 Frontend: https://codescanner.daifend.ai"
    echo "🔧 Backend API: https://codescanner.daifend.ai/api/docs"
else
    echo "❌ Error: Services failed to start"
    echo "Check logs with: docker-compose logs"
    exit 1
fi

echo ""
echo "✨ Deployment complete!"

