#!/bin/bash

# Script to set up backend API subdomain (optional)

set -e

# Configuration
PROJECT_ID="${GCP_PROJECT_ID:-avian-bricolage-475907-f8}"
REGION="${GCP_REGION:-europe-west1}"
BACKEND_SERVICE="${BACKEND_SERVICE_NAME:-vulnerability-scanner-backend}"
BACKEND_DOMAIN="${BACKEND_DOMAIN:-api.stratum.daifend.ai}"

echo "🌐 Setting up backend API domain: $BACKEND_DOMAIN"
echo ""

# Ensure beta component is installed
echo "📦 Checking for gcloud beta component..."
gcloud components install beta --quiet 2>/dev/null || echo "Beta component already installed or installation skipped"

# Create domain mapping for backend
echo "📋 Creating domain mapping for backend service..."
gcloud beta run domain-mappings create \
    --service "$BACKEND_SERVICE" \
    --domain "$BACKEND_DOMAIN" \
    --region "$REGION" \
    --project="$PROJECT_ID"

echo ""
echo "✅ Backend domain mapping created!"
echo ""
echo "📝 IMPORTANT: Add the DNS records shown above to your DNS provider"
echo "   (where you manage daifend.ai domain)"
echo ""
echo "⏳ Wait for DNS propagation (usually 5-30 minutes)"
echo ""
echo "🔍 To check status, run:"
echo "   gcloud beta run domain-mappings describe $BACKEND_DOMAIN --region=$REGION --project=$PROJECT_ID"
echo ""
echo "💡 Note: After the backend domain is active, you can update your frontend"
echo "   to use $BACKEND_DOMAIN instead of the Cloud Run URL for API calls."

