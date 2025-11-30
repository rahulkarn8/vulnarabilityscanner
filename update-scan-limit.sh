#!/bin/bash

# Script to update FREE_SCAN_LIMIT to 5 on Cloud Run service

set -e

# Configuration
PROJECT_ID="${GCP_PROJECT_ID:-avian-bricolage-475907-f8}"
REGION="${GCP_REGION:-europe-west1}"
BACKEND_SERVICE="${BACKEND_SERVICE_NAME:-vulnerability-scanner-backend}"
SCAN_LIMIT="${SCAN_LIMIT:-5}"

echo "🔧 Updating FREE_SCAN_LIMIT to $SCAN_LIMIT on backend service..."

# Update the environment variable
gcloud run services update "$BACKEND_SERVICE" \
    --update-env-vars "FREE_SCAN_LIMIT=$SCAN_LIMIT" \
    --region "$REGION" \
    --project="$PROJECT_ID"

echo ""
echo "✅ FREE_SCAN_LIMIT updated to $SCAN_LIMIT"
echo ""
echo "📋 To verify, check the service:"
echo "   gcloud run services describe $BACKEND_SERVICE --region=$REGION --project=$PROJECT_ID --format='value(spec.template.spec.containers[0].env)'"

