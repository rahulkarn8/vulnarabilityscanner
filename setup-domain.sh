#!/bin/bash

# Quick script to set up custom domain for Cloud Run

set -e

# Configuration
PROJECT_ID="${GCP_PROJECT_ID:-avian-bricolage-475907-f8}"
REGION="${GCP_REGION:-europe-west1}"
FRONTEND_SERVICE="${FRONTEND_SERVICE_NAME:-vulnerability-scanner-frontend}"
BACKEND_SERVICE="${BACKEND_SERVICE_NAME:-vulnerability-scanner-backend}"
DOMAIN="${CUSTOM_DOMAIN:-stratum.daifend.ai}"

echo "🌐 Setting up custom domain: $DOMAIN"
echo ""

# Ensure beta component is installed (required for fully managed Cloud Run)
echo "📦 Checking for gcloud beta component..."
gcloud components install beta --quiet 2>/dev/null || echo "Beta component already installed or installation skipped"

# Create domain mapping (use beta for fully managed Cloud Run)
echo "📋 Creating domain mapping for frontend service..."
gcloud beta run domain-mappings create \
    --service "$FRONTEND_SERVICE" \
    --domain "$DOMAIN" \
    --region "$REGION" \
    --project="$PROJECT_ID"

echo ""
echo "✅ Domain mapping created!"
echo ""
echo "📝 IMPORTANT: Add the DNS records shown above to your DNS provider"
echo "   (where you manage daifend.ai domain)"
echo ""
echo "⏳ Wait for DNS propagation (usually 5-30 minutes, can take up to 48 hours)"
echo ""
echo "🔍 To check status, run:"
echo "   gcloud beta run domain-mappings describe $DOMAIN --region=$REGION --project=$PROJECT_ID"
echo ""
echo "🔧 Once the domain is active, update backend CORS:"
echo "   gcloud run services update $BACKEND_SERVICE \\"
echo "       --update-env-vars \"FRONTEND_URL=https://$DOMAIN,CORS_ORIGINS=https://$DOMAIN\" \\"
echo "       --region=$REGION --project=$PROJECT_ID"

