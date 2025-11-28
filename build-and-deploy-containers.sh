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
docker push "${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/backend:latest"

# Build frontend image
echo -e "\n${GREEN}🔨 Building frontend Docker image...${NC}"
docker build -t "${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/frontend:latest" ./frontend

echo -e "\n${GREEN}📤 Pushing frontend image to Artifact Registry...${NC}"
docker push "${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/frontend:latest"

# Deploy backend to Cloud Run
echo -e "\n${GREEN}🚀 Deploying backend to Cloud Run...${NC}"
gcloud run deploy "$BACKEND_SERVICE" \
    --image "${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/backend:latest" \
    --region "$REGION" \
    --platform managed \
    --allow-unauthenticated \
    --port 8000 \
    --memory 2Gi \
    --cpu 2 \
    --min-instances 0 \
    --max-instances 10 \
    --timeout 300 \
    --set-env-vars "DATABASE_URL=${DATABASE_URL:-},JWT_SECRET_KEY=${JWT_SECRET_KEY:-},GITHUB_CLIENT_ID=${GITHUB_CLIENT_ID:-},GITHUB_CLIENT_SECRET=${GITHUB_CLIENT_SECRET:-},GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID:-},GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET:-},FRONTEND_URL=${FRONTEND_URL:-https://stratum.daifend.ai},CORS_ORIGINS=${FRONTEND_URL:-https://stratum.daifend.ai},OPENAI_API_KEY=${OPENAI_API_KEY:-},STRIPE_SECRET_KEY=${STRIPE_SECRET_KEY:-},STRIPE_PRICE_ID_BASIC=${STRIPE_PRICE_ID_BASIC:-},STRIPE_PRICE_ID_PRO=${STRIPE_PRICE_ID_PRO:-},ADMIN_API_KEY=${ADMIN_API_KEY:-},ADMIN_PASSWORD=${ADMIN_PASSWORD:-},SMTP_SERVER=${SMTP_SERVER:-smtp.gmail.com},SMTP_PORT=${SMTP_PORT:-587},SMTP_USERNAME=${SMTP_USERNAME:-},SMTP_PASSWORD=${SMTP_PASSWORD:-},FROM_EMAIL=${FROM_EMAIL:-},SUPPORT_EMAIL=${SUPPORT_EMAIL:-support@daifend.com},FREE_SCAN_LIMIT=${FREE_SCAN_LIMIT:-5}" \
    --project="$PROJECT_ID"

# Get backend URL
BACKEND_URL=$(gcloud run services describe "$BACKEND_SERVICE" --region="$REGION" --format="value(status.url)" --project="$PROJECT_ID")
echo -e "\n${GREEN}✅ Backend deployed successfully!${NC}"
echo -e "   URL: ${BACKEND_URL}"

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

# Update backend with frontend URL
echo -e "\n${GREEN}🔄 Updating backend with frontend URL...${NC}"
# Update FRONTEND_URL first
gcloud run services update "$BACKEND_SERVICE" \
    --update-env-vars "FRONTEND_URL=${FRONTEND_URL}" \
    --region "$REGION" \
    --project="$PROJECT_ID"
# Then update CORS_ORIGINS (comma-separated list needs to be set as a single value)
# Use semicolon or pipe as separator in the env var string, or update separately
CORS_ORIGINS_VALUE="${FRONTEND_URL},https://stratum.daifend.ai"
gcloud run services update "$BACKEND_SERVICE" \
    --update-env-vars "CORS_ORIGINS=${CORS_ORIGINS_VALUE}" \
    --region "$REGION" \
    --project="$PROJECT_ID"

echo -e "\n${GREEN}🎉 Deployment complete!${NC}\n"
echo -e "${GREEN}📋 Service URLs:${NC}"
echo -e "   Backend:  ${BACKEND_URL}"
echo -e "   Frontend: ${FRONTEND_URL}\n"
echo -e "${YELLOW}⚠️  Important: Update your OAuth redirect URIs:${NC}"
echo -e "   GitHub: ${BACKEND_URL}/auth/github/callback"
echo -e "   Google: ${BACKEND_URL}/auth/google/callback\n"

