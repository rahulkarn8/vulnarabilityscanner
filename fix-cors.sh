#!/bin/bash

# Quick script to fix CORS_ORIGINS to include stratum.daifend.ai

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

# Update the environment variable
gcloud run services update "$BACKEND_SERVICE" \
    --update-env-vars "CORS_ORIGINS=${CORS_ORIGINS_VALUE}" \
    --region "$REGION" \
    --project="$PROJECT_ID"

echo ""
echo "✅ CORS_ORIGINS updated successfully!"
echo ""
echo "📋 To verify, check the service:"
echo "   gcloud run services describe $BACKEND_SERVICE --region=$REGION --project=$PROJECT_ID --format='value(spec.template.spec.containers[0].env)' | grep CORS_ORIGINS"

