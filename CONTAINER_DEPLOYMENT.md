# Container-Based Deployment Guide

This guide shows you how to build Docker containers locally and deploy them directly to Cloud Run, bypassing the Cloud Build trigger configuration issues.

## Prerequisites

1. **Docker** installed locally
2. **gcloud CLI** installed and authenticated
3. **Google Cloud Project** with billing enabled

## Quick Start

### Option 1: Use the Automated Script

```bash
# Set your project ID and region
export GCP_PROJECT_ID="your-project-id"
export GCP_REGION="europe-west1"  # or your preferred region

# Run the deployment script
./build-and-deploy-containers.sh
```

### Option 2: Manual Step-by-Step

#### Step 1: Set Up Environment

```bash
# Set your project
export PROJECT_ID="your-project-id"
export REGION="europe-west1"
export REPO_NAME="vulnerability-scanner"

# Authenticate Docker
gcloud auth configure-docker ${REGION}-docker.pkg.dev
```

#### Step 2: Create Artifact Registry (if needed)

```bash
gcloud artifacts repositories create $REPO_NAME \
    --repository-format=docker \
    --location=$REGION \
    --project=$PROJECT_ID
```

#### Step 3: Build Backend Container

```bash
# Build the image
docker build -t ${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/backend:latest ./backend

# Push to Artifact Registry
docker push ${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/backend:latest
```

#### Step 4: Build Frontend Container

```bash
# Build the image
docker build -t ${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/frontend:latest ./frontend

# Push to Artifact Registry
docker push ${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/frontend:latest
```

#### Step 5: Deploy Backend to Cloud Run

```bash
gcloud run deploy vulnerability-scanner-backend \
    --image ${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/backend:latest \
    --region ${REGION} \
    --platform managed \
    --allow-unauthenticated \
    --port 8000 \
    --memory 2Gi \
    --cpu 2 \
    --min-instances 0 \
    --max-instances 10 \
    --timeout 300 \
    --set-env-vars "DATABASE_URL=...,JWT_SECRET_KEY=...,GITHUB_CLIENT_ID=...,GITHUB_CLIENT_SECRET=...,GOOGLE_CLIENT_ID=...,GOOGLE_CLIENT_SECRET=...,FRONTEND_URL=...,CORS_ORIGINS=...,OPENAI_API_KEY=...,STRIPE_SECRET_KEY=...,STRIPE_PRICE_ID_BASIC=...,STRIPE_PRICE_ID_PRO=...,ADMIN_API_KEY=...,ADMIN_PASSWORD=...,SMTP_SERVER=smtp.gmail.com,SMTP_PORT=587,SMTP_USERNAME=...,SMTP_PASSWORD=...,FROM_EMAIL=...,SUPPORT_EMAIL=support@daifend.com,FREE_SCAN_LIMIT=5"
```

#### Step 6: Get Backend URL

```bash
BACKEND_URL=$(gcloud run services describe vulnerability-scanner-backend \
    --region=${REGION} \
    --format="value(status.url)")
echo "Backend URL: $BACKEND_URL"
```

#### Step 7: Deploy Frontend to Cloud Run

```bash
gcloud run deploy vulnerability-scanner-frontend \
    --image ${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/frontend:latest \
    --region ${REGION} \
    --platform managed \
    --allow-unauthenticated \
    --port 80 \
    --memory 512Mi \
    --cpu 1 \
    --min-instances 0 \
    --max-instances 5
```

#### Step 8: Update Backend with Frontend URL

```bash
FRONTEND_URL=$(gcloud run services describe vulnerability-scanner-frontend \
    --region=${REGION} \
    --format="value(status.url)")

gcloud run services update vulnerability-scanner-backend \
    --update-env-vars "FRONTEND_URL=${FRONTEND_URL},CORS_ORIGINS=${FRONTEND_URL},https://stratum.daifend.ai" \
    --region=${REGION}
```

## Advantages of Container-Based Deployment

1. **No Trigger Configuration Issues**: Bypasses Cloud Build trigger problems
2. **Faster Iterations**: Build and deploy without waiting for Cloud Build
3. **Local Testing**: Test containers locally before deploying
4. **More Control**: Full control over the build process
5. **Easier Debugging**: See build output directly

## Updating Deployments

When you make code changes:

```bash
# Rebuild and redeploy backend
docker build -t ${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/backend:latest ./backend
docker push ${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/backend:latest
gcloud run deploy vulnerability-scanner-backend \
    --image ${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/backend:latest \
    --region ${REGION}

# Rebuild and redeploy frontend
docker build -t ${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/frontend:latest ./frontend
docker push ${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/frontend:latest
gcloud run deploy vulnerability-scanner-frontend \
    --image ${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/frontend:latest \
    --region ${REGION}
```

## Environment Variables

Make sure to set all required environment variables. You can:

1. **Use a .env file** (the script will load it automatically)
2. **Set them in the deployment command** (as shown above)
3. **Update them later**:

```bash
gcloud run services update vulnerability-scanner-backend \
    --update-env-vars "KEY=VALUE,KEY2=VALUE2" \
    --region=${REGION}
```

## Troubleshooting

### Docker Build Fails

```bash
# Check Docker is running
docker ps

# Try building with verbose output
docker build --progress=plain -t test-image ./backend
```

### Push Fails

```bash
# Re-authenticate Docker
gcloud auth configure-docker ${REGION}-docker.pkg.dev

# Check permissions
gcloud projects get-iam-policy $PROJECT_ID
```

### Deployment Fails

```bash
# Check service logs
gcloud run services logs read vulnerability-scanner-backend --region=${REGION}

# Check service status
gcloud run services describe vulnerability-scanner-backend --region=${REGION}
```

## Next Steps

After deployment:
1. Map custom domain (if needed)
2. Update OAuth redirect URIs
3. Set up monitoring and alerts
4. Configure database connection

