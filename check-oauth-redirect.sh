#!/bin/bash

# Script to check and fix OAuth redirect configuration

set -e

PROJECT_ID="${GCP_PROJECT_ID:-avian-bricolage-475907-f8}"
REGION="${GCP_REGION:-europe-west1}"
BACKEND_SERVICE="${BACKEND_SERVICE_NAME:-vulnerability-scanner-backend}"
FRONTEND_SERVICE="${FRONTEND_SERVICE_NAME:-vulnerability-scanner-frontend}"

echo "🔍 Checking OAuth redirect configuration..."

# Get current URLs
BACKEND_URL=$(gcloud run services describe "$BACKEND_SERVICE" --region="$REGION" --format="value(status.url)" --project="$PROJECT_ID" 2>/dev/null || echo "")
FRONTEND_URL=$(gcloud run services describe "$FRONTEND_SERVICE" --region="$REGION" --format="value(status.url)" --project="$PROJECT_ID" 2>/dev/null || echo "")

echo ""
echo "📋 Current URLs:"
echo "   Backend:  ${BACKEND_URL}"
echo "   Frontend: ${FRONTEND_URL}"
echo ""

# Check environment variables
echo "🔍 Checking backend environment variables..."
ENV_VARS=$(gcloud run services describe "$BACKEND_SERVICE" --region="$REGION" --format="yaml(spec.template.spec.containers[0].env)" --project="$PROJECT_ID" 2>/dev/null || echo "")

FRONTEND_URL_ENV=$(echo "$ENV_VARS" | grep -A1 "name: FRONTEND_URL" | grep "value:" | awk '{print $2}' || echo "NOT SET")
GITHUB_REDIRECT_URI_ENV=$(echo "$ENV_VARS" | grep -A1 "name: GITHUB_REDIRECT_URI" | grep "value:" | awk '{print $2}' || echo "NOT SET")

echo "   FRONTEND_URL: ${FRONTEND_URL_ENV}"
echo "   GITHUB_REDIRECT_URI: ${GITHUB_REDIRECT_URI_ENV}"
echo ""

# Expected values
EXPECTED_FRONTEND_URL="${FRONTEND_URL}"
EXPECTED_GITHUB_REDIRECT="${BACKEND_URL}/auth/github/callback"

echo "✅ Expected values:"
echo "   FRONTEND_URL should be: ${EXPECTED_FRONTEND_URL}"
echo "   GITHUB_REDIRECT_URI should be: ${EXPECTED_GITHUB_REDIRECT}"
echo ""

# Check if updates are needed
NEEDS_UPDATE=false

if [ "$FRONTEND_URL_ENV" != "$EXPECTED_FRONTEND_URL" ]; then
    echo "⚠️  FRONTEND_URL needs to be updated"
    NEEDS_UPDATE=true
fi

if [ "$GITHUB_REDIRECT_URI_ENV" != "$EXPECTED_GITHUB_REDIRECT" ]; then
    echo "⚠️  GITHUB_REDIRECT_URI needs to be updated"
    NEEDS_UPDATE=true
fi

if [ "$NEEDS_UPDATE" = true ]; then
    echo ""
    echo "🔧 Updating environment variables..."
    
    # Update FRONTEND_URL
    if [ "$FRONTEND_URL_ENV" != "$EXPECTED_FRONTEND_URL" ]; then
        echo "   Updating FRONTEND_URL..."
        gcloud run services update "$BACKEND_SERVICE" \
            --update-env-vars "FRONTEND_URL=${EXPECTED_FRONTEND_URL}" \
            --region "$REGION" \
            --project="$PROJECT_ID" || echo "   ⚠️  Failed to update FRONTEND_URL"
    fi
    
    # Update GITHUB_REDIRECT_URI
    if [ "$GITHUB_REDIRECT_URI_ENV" != "$EXPECTED_GITHUB_REDIRECT" ]; then
        echo "   Updating GITHUB_REDIRECT_URI..."
        gcloud run services update "$BACKEND_SERVICE" \
            --update-env-vars "GITHUB_REDIRECT_URI=${EXPECTED_GITHUB_REDIRECT}" \
            --region "$REGION" \
            --project="$PROJECT_ID" || {
            echo "   ⚠️  Failed to update GITHUB_REDIRECT_URI automatically"
            echo "   Please update manually in Cloud Console:"
            echo "   ${EXPECTED_GITHUB_REDIRECT}"
        }
    fi
    
    echo ""
    echo "✅ Environment variables updated!"
else
    echo "✅ All environment variables are correctly set!"
fi

echo ""
echo "📝 Next steps:"
echo "   1. Make sure your GitHub OAuth app has this callback URL:"
echo "      ${EXPECTED_GITHUB_REDIRECT}"
echo ""
echo "   2. After OAuth, you should be redirected to:"
echo "      ${EXPECTED_FRONTEND_URL}/?token=...&user_id=..."
echo ""
echo "   3. Check browser console for OAuth callback logs"

