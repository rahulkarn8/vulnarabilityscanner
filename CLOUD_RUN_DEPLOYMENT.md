# Google Cloud Run Deployment Guide

This guide will help you deploy the Vulnerability Scanner to Google Cloud Run.

**Production Domain**: `stratum.daifend.ai`

## Prerequisites

1. **Google Cloud Account** with billing enabled
2. **gcloud CLI** installed and configured
   ```bash
   # Install gcloud CLI
   # macOS: brew install google-cloud-sdk
   # Or download from: https://cloud.google.com/sdk/docs/install
   
   # Authenticate
   gcloud auth login
   ```

3. **Docker** installed locally (for building images)

## Step 1: Initial Setup

### 1.1 Set up Google Cloud Project

```bash
# Set your project ID
export GCP_PROJECT_ID="your-project-id"
gcloud config set project $GCP_PROJECT_ID

# Enable required APIs
gcloud services enable \
    cloudbuild.googleapis.com \
    run.googleapis.com \
    artifactregistry.googleapis.com
```

### 1.2 Create Artifact Registry Repository

```bash
# Set region (e.g., us-central1, us-east1, europe-west1)
export GCP_REGION="us-central1"
export REPO_NAME="vulnerability-scanner"

# Create repository
gcloud artifacts repositories create $REPO_NAME \
    --repository-format=docker \
    --location=$GCP_REGION
```

### 1.3 Configure Docker Authentication

```bash
gcloud auth configure-docker ${GCP_REGION}-docker.pkg.dev
```

## Step 2: Environment Variables

Create a `.env` file in the project root with all required variables:

```env
# Google Cloud Configuration
GCP_PROJECT_ID=your-project-id
GCP_REGION=us-central1

# Database (required - use Cloud SQL or external database)
DATABASE_URL=postgresql://user:password@host:port/database
# or
DATABASE_URL=mysql://user:password@host:port/database

# JWT Secret (generate a strong random string)
JWT_SECRET_KEY=your-very-secure-random-secret-key-here

# GitHub OAuth
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret

# Google OAuth
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret

# Frontend URL (will be set after deployment)
FRONTEND_URL=https://your-frontend-service.run.app

# OpenAI API (optional)
OPENAI_API_KEY=your_openai_api_key

# Stripe (for payments)
STRIPE_SECRET_KEY=your_stripe_secret_key
STRIPE_PRICE_ID_BASIC=price_id_for_basic_plan
STRIPE_PRICE_ID_PRO=price_id_for_pro_plan

# Admin Access (optional)
ADMIN_API_KEY=your_secure_admin_api_key
ADMIN_PASSWORD=your_secure_admin_password

# Support Email
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password
FROM_EMAIL=your_email@gmail.com
SUPPORT_EMAIL=support@daifend.com

# Scan Limits
FREE_SCAN_LIMIT=5
```

## Step 3: Deploy to Cloud Run

### Option A: Using the Deployment Script (Recommended)

```bash
# Make script executable
chmod +x deploy-cloudrun.sh

# Set environment variables
export GCP_PROJECT_ID="your-project-id"
export GCP_REGION="us-central1"

# Run deployment
./deploy-cloudrun.sh
```

### Option B: Manual Deployment

#### 3.1 Build and Push Backend

```bash
# Build backend image
docker build -t ${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/${REPO_NAME}/backend:latest ./backend

# Push to Artifact Registry
docker push ${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/${REPO_NAME}/backend:latest
```

#### 3.2 Deploy Backend to Cloud Run

```bash
gcloud run deploy vulnerability-scanner-backend \
    --image ${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/${REPO_NAME}/backend:latest \
    --region ${GCP_REGION} \
    --platform managed \
    --allow-unauthenticated \
    --port 8000 \
    --memory 2Gi \
    --cpu 2 \
    --min-instances 0 \
    --max-instances 10 \
    --timeout 300 \
    --set-env-vars "DATABASE_URL=${DATABASE_URL},JWT_SECRET_KEY=${JWT_SECRET_KEY},GITHUB_CLIENT_ID=${GITHUB_CLIENT_ID},GITHUB_CLIENT_SECRET=${GITHUB_CLIENT_SECRET},GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID},GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET},FRONTEND_URL=${FRONTEND_URL},OPENAI_API_KEY=${OPENAI_API_KEY},STRIPE_SECRET_KEY=${STRIPE_SECRET_KEY},STRIPE_PRICE_ID_BASIC=${STRIPE_PRICE_ID_BASIC},STRIPE_PRICE_ID_PRO=${STRIPE_PRICE_ID_PRO},ADMIN_API_KEY=${ADMIN_API_KEY},ADMIN_PASSWORD=${ADMIN_PASSWORD},SMTP_SERVER=${SMTP_SERVER},SMTP_PORT=${SMTP_PORT},SMTP_USERNAME=${SMTP_USERNAME},SMTP_PASSWORD=${SMTP_PASSWORD},FROM_EMAIL=${FROM_EMAIL},SUPPORT_EMAIL=${SUPPORT_EMAIL},FREE_SCAN_LIMIT=${FREE_SCAN_LIMIT}"
```

#### 3.3 Get Backend URL

```bash
BACKEND_URL=$(gcloud run services describe vulnerability-scanner-backend \
    --region=${GCP_REGION} \
    --format="value(status.url)")
echo "Backend URL: $BACKEND_URL"
```

#### 3.4 Build and Push Frontend

```bash
# Update frontend config with backend URL
# The frontend will use VITE_API_URL environment variable or detect from window.location

# Build frontend image
docker build -t ${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/${REPO_NAME}/frontend:latest ./frontend

# Push to Artifact Registry
docker push ${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/${REPO_NAME}/frontend:latest
```

#### 3.5 Deploy Frontend to Cloud Run

```bash
gcloud run deploy vulnerability-scanner-frontend \
    --image ${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/${REPO_NAME}/frontend:latest \
    --region ${GCP_REGION} \
    --platform managed \
    --allow-unauthenticated \
    --port 80 \
    --memory 512Mi \
    --cpu 1 \
    --min-instances 0 \
    --max-instances 5 \
    --set-env-vars "VITE_API_URL=${BACKEND_URL}"
```

#### 3.6 Update Backend with Frontend URL

```bash
FRONTEND_URL=$(gcloud run services describe vulnerability-scanner-frontend \
    --region=${GCP_REGION} \
    --format="value(status.url)")

gcloud run services update vulnerability-scanner-backend \
    --update-env-vars "FRONTEND_URL=${FRONTEND_URL},CORS_ORIGINS=${FRONTEND_URL},https://stratum.daifend.ai" \
    --region=${GCP_REGION}
```

### Option C: Using Cloud Build (CI/CD)

```bash
# Submit build to Cloud Build (explicitly specify the config file)
gcloud builds submit --config=cloudbuild.yaml .

# Or trigger from source repository
gcloud builds triggers create github \
    --repo-name=vulnarabilityscanner \
    --repo-owner=rahulkarn8 \
    --branch-pattern="^main$" \
    --build-config=cloudbuild.yaml \
    --name=vulnerability-scanner-build

# If you have an existing trigger, update it:
gcloud builds triggers update vulnerability-scanner-build \
    --build-config=cloudbuild.yaml
```

**Important**: Make sure your Cloud Build trigger is configured to use `cloudbuild.yaml`. If you're seeing errors about missing Dockerfile, the trigger might be using Cloud Run's automatic build instead of your custom config.

## Step 4: Update OAuth Redirect URIs

After deployment, update your OAuth provider redirect URIs:

### GitHub OAuth
1. Go to GitHub Settings → Developer settings → OAuth Apps
2. Update Authorization callback URL to: `https://your-backend-url.run.app/auth/github/callback`

### Google OAuth
1. Go to Google Cloud Console → APIs & Services → Credentials
2. Update Authorized redirect URI to: `https://your-backend-url.run.app/auth/google/callback`

## Step 5: Custom Domain (Optional)

### 5.1 Map Custom Domain to Cloud Run

```bash
# Map domain to frontend service
gcloud run domain-mappings create \
    --service vulnerability-scanner-frontend \
    --domain stratum.daifend.ai \
    --region ${GCP_REGION}

# Map domain to backend service (if using subdomain)
gcloud run domain-mappings create \
    --service vulnerability-scanner-backend \
    --domain api.stratum.daifend.ai \
    --region ${GCP_REGION}
```

### 5.2 Update DNS Records

Add the CNAME records provided by Cloud Run to your DNS provider.

## Step 6: Database Setup

### Option A: Cloud SQL (Recommended)

```bash
# Create Cloud SQL instance
gcloud sql instances create vulnerability-scanner-db \
    --database-version=POSTGRES_15 \
    --tier=db-f1-micro \
    --region=${GCP_REGION}

# Create database
gcloud sql databases create vulnerabilityscanner \
    --instance=vulnerability-scanner-db

# Create user
gcloud sql users create scanner \
    --instance=vulnerability-scanner-db \
    --password=your-secure-password

# Get connection name
CONNECTION_NAME=$(gcloud sql instances describe vulnerability-scanner-db \
    --format="value(connectionName)")

# Connect Cloud Run to Cloud SQL
gcloud run services update vulnerability-scanner-backend \
    --add-cloudsql-instances=$CONNECTION_NAME \
    --region=${GCP_REGION}
```

Update `DATABASE_URL` in Cloud Run:
```bash
gcloud run services update vulnerability-scanner-backend \
    --update-env-vars "DATABASE_URL=postgresql://scanner:password@/${CONNECTION_NAME}/vulnerabilityscanner?host=/cloudsql/${CONNECTION_NAME}" \
    --region=${GCP_REGION}
```

### Option B: External Database

Use your existing PostgreSQL or MySQL database URL in the `DATABASE_URL` environment variable.

## Step 7: Monitoring and Logs

### View Logs

```bash
# Backend logs
gcloud run services logs read vulnerability-scanner-backend --region=${GCP_REGION}

# Frontend logs
gcloud run services logs read vulnerability-scanner-frontend --region=${GCP_REGION}
```

### Monitor Services

```bash
# List services
gcloud run services list --region=${GCP_REGION}

# Get service details
gcloud run services describe vulnerability-scanner-backend --region=${GCP_REGION}
```

## Step 8: Update Environment Variables

To update environment variables after deployment:

```bash
# Update backend
gcloud run services update vulnerability-scanner-backend \
    --update-env-vars "KEY=VALUE,KEY2=VALUE2" \
    --region=${GCP_REGION}

# Update frontend
gcloud run services update vulnerability-scanner-frontend \
    --update-env-vars "KEY=VALUE" \
    --region=${GCP_REGION}
```

## Troubleshooting

### Common Issues

1. **Port binding errors**: Cloud Run automatically sets the `PORT` environment variable. The Dockerfile uses `${PORT:-8000}` to handle this.

2. **CORS errors**: Make sure `FRONTEND_URL` and `CORS_ORIGINS` are set correctly in the backend service.

3. **Database connection issues**: 
   - For Cloud SQL, ensure the Cloud Run service has the Cloud SQL connection configured
   - Check that the database is accessible from Cloud Run's network

4. **Image pull errors**: Ensure Docker images are pushed to Artifact Registry and the service account has permissions.

### Check Service Status

```bash
# Check backend health
curl https://your-backend-url.run.app/

# Check frontend
curl https://your-frontend-url.run.app/
```

## Cost Optimization

- **Min instances**: Set to 0 to scale to zero when not in use
- **Max instances**: Adjust based on expected traffic
- **Memory/CPU**: Start with lower values and scale up if needed
- **Timeout**: Set appropriate timeout values (max 300s for Cloud Run)

## Security Best Practices

1. **Use Secret Manager** for sensitive values:
   ```bash
   # Create secret
   echo -n "your-secret-value" | gcloud secrets create jwt-secret-key --data-file=-
   
   # Use in Cloud Run
   gcloud run services update vulnerability-scanner-backend \
       --update-secrets JWT_SECRET_KEY=jwt-secret-key:latest \
       --region=${GCP_REGION}
   ```

2. **Enable IAM authentication** for internal services (optional)

3. **Use VPC connector** if connecting to private resources

## Next Steps

1. Set up custom domain
2. Configure SSL certificates (automatic with Cloud Run)
3. Set up monitoring and alerts
4. Configure backup for database
5. Set up CI/CD pipeline

