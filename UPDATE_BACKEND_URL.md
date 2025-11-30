# Update Backend API URL in Frontend

The frontend needs to know the backend Cloud Run URL to make API calls. Since the backend is not mapped to a custom domain, we need to use its Cloud Run URL.

## Get Your Backend URL

Run this command to get your backend Cloud Run URL:

```bash
gcloud run services describe vulnerability-scanner-backend \
    --region europe-west1 \
    --project avian-bricolage-475907-f8 \
    --format="value(status.url)"
```

## Update Frontend Config

1. Copy the backend URL from above
2. Update `frontend/src/config.ts`:
   - Replace the hardcoded URL with your actual backend URL
   - Or better: Set `VITE_API_URL` environment variable during build

## Option 1: Update config.ts directly

Edit `frontend/src/config.ts` and replace the backend URL.

## Option 2: Use Environment Variable (Recommended)

Set `VITE_API_URL` when building the frontend:

```bash
export BACKEND_URL=$(gcloud run services describe vulnerability-scanner-backend \
    --region europe-west1 \
    --project avian-bricolage-475907-f8 \
    --format="value(status.url)")

# Build frontend with backend URL
cd frontend
VITE_API_URL=$BACKEND_URL npm run build
```

Or update the deployment script to set this automatically.

