#!/bin/bash

# Simple script to fix CORS_ORIGINS - updates FRONTEND_URL and CORS_ORIGINS separately

set -e

PROJECT_ID="${GCP_PROJECT_ID:-avian-bricolage-475907-f8}"
REGION="${GCP_REGION:-europe-west1}"
BACKEND_SERVICE="${BACKEND_SERVICE_NAME:-vulnerability-scanner-backend}"

echo "🔧 Updating CORS_ORIGINS to include stratum.daifend.ai..."

# Get current frontend URL
FRONTEND_URL=$(gcloud run services describe vulnerability-scanner-frontend --region="$REGION" --format="value(status.url)" --project="$PROJECT_ID" 2>/dev/null || echo "")

# Set CORS_ORIGINS to include both frontend URL and custom domain
if [ -n "$FRONTEND_URL" ]; then
    CORS_ORIGINS_VALUE="${FRONTEND_URL},https://stratum.daifend.ai"
else
    CORS_ORIGINS_VALUE="https://stratum.daifend.ai"
fi

echo "   Setting CORS_ORIGINS to: $CORS_ORIGINS_VALUE"

# Update FRONTEND_URL first (if we have it)
if [ -n "$FRONTEND_URL" ]; then
    echo "   Updating FRONTEND_URL..."
    gcloud run services update "$BACKEND_SERVICE" \
        --update-env-vars "FRONTEND_URL=${FRONTEND_URL}" \
        --region "$REGION" \
        --project="$PROJECT_ID"
fi

# Update CORS_ORIGINS - use a workaround: set it via Cloud Console API or use base64 encoding
# The issue is that gcloud parses commas in --update-env-vars as separators
# Solution: Use --set-env-vars with all existing env vars, or update via Cloud Console

echo "   Updating CORS_ORIGINS..."
echo "   Note: This may fail due to comma parsing. If it fails, use Cloud Console to update manually."

# Try with quotes around the value
gcloud run services update "$BACKEND_SERVICE" \
    --update-env-vars "CORS_ORIGINS=\"${CORS_ORIGINS_VALUE}\"" \
    --region "$REGION" \
    --project="$PROJECT_ID" 2>&1 || {
    echo ""
    echo "❌ Failed to update CORS_ORIGINS automatically."
    echo ""
    echo "📋 Manual fix required:"
    echo "   1. Go to: https://console.cloud.google.com/run/detail/${REGION}/${BACKEND_SERVICE}"
    echo "   2. Click 'Edit & Deploy New Revision'"
    echo "   3. Go to 'Variables & Secrets' tab"
    echo "   4. Find 'CORS_ORIGINS' and set it to:"
    echo "      ${CORS_ORIGINS_VALUE}"
    echo "   5. Click 'Deploy'"
    echo ""
    exit 1
}

echo ""
echo "✅ CORS_ORIGINS updated successfully!"

