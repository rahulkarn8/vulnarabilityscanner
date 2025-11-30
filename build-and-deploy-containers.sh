#!/bin/bash

# Build and Deploy Containers to Cloud Run
# This script builds Docker images locally, pushes them to Artifact Registry,
# and deploys to Cloud Run - bypassing the Cloud Build trigger issue

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration - UPDATE THESE VALUES
PROJECT_ID="${GCP_PROJECT_ID:-avian-bricolage-475907-f8}"
REGION="${GCP_REGION:-europe-west1}"
REPO_NAME="${GCP_REPO_NAME:-vulnerability-scanner}"
BACKEND_SERVICE="${BACKEND_SERVICE_NAME:-vulnerability-scanner-backend}"
FRONTEND_SERVICE="${FRONTEND_SERVICE_NAME:-vulnerability-scanner-frontend}"

echo -e "${GREEN}🐳 Building and Deploying Containers to Cloud Run${NC}\n"

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo -e "${RED}❌ Error: gcloud CLI is not installed.${NC}"
    echo "Please install it from: https://cloud.google.com/sdk/docs/install"
    exit 1
fi

# Check if docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Error: Docker is not installed.${NC}"
    exit 1
fi

# Set project
echo -e "${GREEN}📋 Setting GCP project to: ${PROJECT_ID}${NC}"
gcloud config set project "$PROJECT_ID"

# Enable required APIs
echo -e "\n${GREEN}🔧 Enabling required Google Cloud APIs...${NC}"
gcloud services enable \
    run.googleapis.com \
    artifactregistry.googleapis.com \
    --project="$PROJECT_ID" 2>/dev/null || true

# Create Artifact Registry repository if it doesn't exist
echo -e "\n${GREEN}📦 Setting up Artifact Registry...${NC}"
if ! gcloud artifacts repositories describe "$REPO_NAME" --location="$REGION" --project="$PROJECT_ID" &>/dev/null; then
    echo "Creating Artifact Registry repository: $REPO_NAME"
    gcloud artifacts repositories create "$REPO_NAME" \
        --repository-format=docker \
        --location="$REGION" \
        --project="$PROJECT_ID"
else
    echo "Artifact Registry repository already exists"
fi

# Configure Docker to use gcloud as credential helper
echo -e "\n${GREEN}🐳 Configuring Docker authentication...${NC}"
gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet

# Configure Docker to bypass proxy for Artifact Registry (if proxy is causing issues)
# This prevents timeout errors when pushing to Artifact Registry
if docker info 2>/dev/null | grep -q "HTTP Proxy"; then
    echo -e "${YELLOW}⚠️  Docker proxy detected. Configuring NO_PROXY for Artifact Registry...${NC}"
    export NO_PROXY="${NO_PROXY},${REGION}-docker.pkg.dev,*.pkg.dev"
    export no_proxy="${no_proxy},${REGION}-docker.pkg.dev,*.pkg.dev"
fi

# Load environment variables from .env file if it exists
if [ -f .env ]; then
    echo -e "\n${GREEN}📝 Loading environment variables from .env file...${NC}"
    export $(grep -v '^#' .env | xargs)
else
    echo -e "${YELLOW}⚠️  No .env file found. Using environment variables or defaults.${NC}"
fi

# Build backend image
echo -e "\n${GREEN}🔨 Building backend Docker image...${NC}"
docker build -t "${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/backend:latest" ./backend

echo -e "\n${GREEN}📤 Pushing backend image to Artifact Registry...${NC}"
# Temporarily disable proxy for Artifact Registry push to avoid timeout
HTTP_PROXY_BACKUP=$HTTP_PROXY
HTTPS_PROXY_BACKUP=$HTTPS_PROXY
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy
docker push "${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/backend:latest" || {
    # Restore proxy settings if push fails
    export HTTP_PROXY=$HTTP_PROXY_BACKUP
    export HTTPS_PROXY=$HTTPS_PROXY_BACKUP
    exit 1
}
export HTTP_PROXY=$HTTP_PROXY_BACKUP
export HTTPS_PROXY=$HTTPS_PROXY_BACKUP

# Deploy backend to Cloud Run FIRST (we need its URL for frontend build)
echo -e "\n${GREEN}🚀 Deploying backend to Cloud Run...${NC}"
gcloud run deploy "$BACKEND_SERVICE" \
    --image "${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/backend:latest" \
    --region "$REGION" \
    --platform managed \
    --allow-unauthenticated \
    --port 8000 \
    --memory 2Gi \
    --cpu 2 \
    --min-instances 1 \
    --max-instances 10 \
    --timeout 600 \
    --cpu-boost \
    --set-env-vars "DATABASE_URL=${DATABASE_URL:-},JWT_SECRET_KEY=${JWT_SECRET_KEY:-},GITHUB_CLIENT_ID=${GITHUB_CLIENT_ID:-},GITHUB_CLIENT_SECRET=${GITHUB_CLIENT_SECRET:-},GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID:-},GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET:-},OPENAI_API_KEY=${OPENAI_API_KEY:-},STRIPE_SECRET_KEY=${STRIPE_SECRET_KEY:-},STRIPE_PRICE_ID_BASIC=${STRIPE_PRICE_ID_BASIC:-},STRIPE_PRICE_ID_PRO=${STRIPE_PRICE_ID_PRO:-},ADMIN_API_KEY=${ADMIN_API_KEY:-},ADMIN_PASSWORD=${ADMIN_PASSWORD:-},SMTP_SERVER=${SMTP_SERVER:-smtp.gmail.com},SMTP_PORT=${SMTP_PORT:-587},SMTP_USERNAME=${SMTP_USERNAME:-},SMTP_PASSWORD=${SMTP_PASSWORD:-ypht ltua gvdz lilj},FROM_EMAIL=${FROM_EMAIL:-},SUPPORT_EMAIL=${SUPPORT_EMAIL:-support@daifend.com},FREE_SCAN_LIMIT=${FREE_SCAN_LIMIT:-5},CORS_ORIGINS=${CORS_ORIGINS:-https://vulnerability-scanner-frontend-oi4goiciua-ew.a.run.app,https://stratum.daifend.ai}" \
    --project="$PROJECT_ID"

# Get backend URL (needed for frontend build and OAuth redirect URIs)
BACKEND_URL=$(gcloud run services describe "$BACKEND_SERVICE" --region="$REGION" --format="value(status.url)" --project="$PROJECT_ID")
echo -e "\n${GREEN}✅ Backend deployed successfully!${NC}"
echo -e "   URL: ${BACKEND_URL}"

# Update backend with OAuth redirect URIs (must use backend Cloud Run URL, not custom domain)
echo -e "\n${GREEN}🔄 Updating backend with OAuth redirect URIs...${NC}"
GITHUB_REDIRECT_URI="${BACKEND_URL}/auth/github/callback"
GOOGLE_REDIRECT_URI="${BACKEND_URL}/auth/google/callback"
echo "   GITHUB_REDIRECT_URI: ${GITHUB_REDIRECT_URI}"
echo "   GOOGLE_REDIRECT_URI: ${GOOGLE_REDIRECT_URI}"

# Update OAuth redirect URIs and SMTP password
echo -e "\n${GREEN}🔄 Updating backend with OAuth redirect URIs and SMTP password...${NC}"
SMTP_PASSWORD_VALUE="${SMTP_PASSWORD:-ypht ltua gvdz lilj}"
gcloud run services update "$BACKEND_SERVICE" \
    --update-env-vars "GITHUB_REDIRECT_URI=${GITHUB_REDIRECT_URI},GOOGLE_REDIRECT_URI=${GOOGLE_REDIRECT_URI},SMTP_PASSWORD=${SMTP_PASSWORD_VALUE}" \
    --region "$REGION" \
    --project="$PROJECT_ID"

# Build frontend image WITH backend URL (build happens after backend is deployed)
echo -e "\n${GREEN}🔨 Building frontend Docker image with backend URL: ${BACKEND_URL}...${NC}"
# Build frontend with backend URL as build argument
docker build \
    --build-arg VITE_API_URL="${BACKEND_URL}" \
    -t "${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/frontend:latest" \
    ./frontend

echo -e "\n${GREEN}📤 Pushing frontend image to Artifact Registry...${NC}"
# Temporarily disable proxy for Artifact Registry push to avoid timeout
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy
docker push "${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/frontend:latest" || {
    # Restore proxy settings if push fails
    export HTTP_PROXY=$HTTP_PROXY_BACKUP
    export HTTPS_PROXY=$HTTPS_PROXY_BACKUP
    exit 1
}
export HTTP_PROXY=$HTTP_PROXY_BACKUP
export HTTPS_PROXY=$HTTPS_PROXY_BACKUP

# Deploy frontend to Cloud Run
echo -e "\n${GREEN}🚀 Deploying frontend to Cloud Run...${NC}"
gcloud run deploy "$FRONTEND_SERVICE" \
    --image "${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/frontend:latest" \
    --region "$REGION" \
    --platform managed \
    --allow-unauthenticated \
    --port 80 \
    --memory 512Mi \
    --cpu 1 \
    --min-instances 0 \
    --max-instances 5 \
    --project="$PROJECT_ID"

# Get frontend URL
FRONTEND_URL=$(gcloud run services describe "$FRONTEND_SERVICE" --region="$REGION" --format="value(status.url)" --project="$PROJECT_ID")
echo -e "\n${GREEN}✅ Frontend deployed successfully!${NC}"
echo -e "   URL: ${FRONTEND_URL}"

# Update backend with frontend URL (use Cloud Run URLs since custom domain not set up yet)
echo -e "\n${GREEN}🔄 Updating backend with frontend URL and CORS_ORIGINS...${NC}"
# Build CORS_ORIGINS value (comma-separated list) - include both Cloud Run URL and custom domain
# Use the specified value or default to the provided URLs
CORS_ORIGINS_VALUE="${CORS_ORIGINS:-https://vulnerability-scanner-frontend-oi4goiciua-ew.a.run.app,https://stratum.daifend.ai}"

echo "Setting FRONTEND_URL=${FRONTEND_URL}"
echo "Setting CORS_ORIGINS=${CORS_ORIGINS_VALUE}"

# Update FRONTEND_URL first
gcloud run services update "$BACKEND_SERVICE" \
    --update-env-vars "FRONTEND_URL=${FRONTEND_URL}" \
    --region "$REGION" \
    --project="$PROJECT_ID"

# Update CORS_ORIGINS separately - use quotes to handle comma in value
# The issue is that gcloud parses commas as separators, so we need to escape or quote properly
echo -e "${YELLOW}⚠️  Note: CORS_ORIGINS update may fail due to comma parsing.${NC}"
echo -e "${YELLOW}   If it fails, update manually in Cloud Console:${NC}"
echo -e "${YELLOW}   CORS_ORIGINS=${CORS_ORIGINS_VALUE}${NC}"

# Try to update CORS_ORIGINS - this may fail due to comma parsing
gcloud run services update "$BACKEND_SERVICE" \
    --update-env-vars "CORS_ORIGINS=${CORS_ORIGINS_VALUE}" \
    --region "$REGION" \
    --project="$PROJECT_ID" 2>&1 || {
    echo -e "${YELLOW}⚠️  Failed to update CORS_ORIGINS automatically.${NC}"
    echo -e "${YELLOW}   Please update it manually in Cloud Console:${NC}"
    echo -e "${YELLOW}   1. Go to: https://console.cloud.google.com/run/detail/${REGION}/${BACKEND_SERVICE}${NC}"
    echo -e "${YELLOW}   2. Click 'Edit & Deploy New Revision'${NC}"
    echo -e "${YELLOW}   3. Go to 'Variables & Secrets' tab${NC}"
    echo -e "${YELLOW}   4. Set CORS_ORIGINS to: ${CORS_ORIGINS_VALUE}${NC}"
    echo -e "${YELLOW}   5. Click 'Deploy'${NC}"
}

echo -e "\n${GREEN}🎉 Deployment complete!${NC}\n"
echo -e "${GREEN}📋 Service URLs:${NC}"
echo -e "   Backend:  ${BACKEND_URL}"
echo -e "   Frontend: ${FRONTEND_URL}\n"
echo -e "${YELLOW}⚠️  Important: Update your OAuth redirect URIs:${NC}"
echo -e "   GitHub: ${BACKEND_URL}/auth/github/callback"
echo -e "   Google: ${BACKEND_URL}/auth/google/callback\n"

