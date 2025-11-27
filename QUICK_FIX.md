# Quick Fix for Cloud Build Error

## The Problem
Your Cloud Build is trying to use a default Dockerfile build instead of your `cloudbuild.yaml` file.

## The Solution (Choose One)

### ✅ EASIEST: Update via Google Cloud Console

1. **Go to Cloud Build Triggers**: https://console.cloud.google.com/cloud-build/triggers
2. **Find your trigger** for `vulnarabilityscanner` repository
3. **Click "Edit"**
4. **Under "Configuration" section**:
   - Change from "Dockerfile" or "Automatic" 
   - To: **"Cloud Build configuration file (yaml or json)"**
   - Location: **`cloudbuild.yaml`**
5. **Click "Save"**
6. **Push a new commit** or manually trigger the build

### Alternative: Command Line Fix

```bash
# 1. List your triggers to find the name
gcloud builds triggers list

# 2. Update the trigger (replace TRIGGER_NAME with actual name)
gcloud builds triggers update TRIGGER_NAME \
    --build-config=cloudbuild.yaml

# 3. Or if that doesn't work, delete and recreate:
gcloud builds triggers delete TRIGGER_NAME

gcloud builds triggers create github \
    --repo-name=vulnarabilityscanner \
    --repo-owner=rahulkarn8 \
    --branch-pattern="^main$" \
    --build-config=cloudbuild.yaml \
    --name=vulnerability-scanner-build
```

### Test the Build Manually

After fixing the trigger, you can test it manually:

```bash
gcloud builds submit --config=cloudbuild.yaml .
```

## Why This Happens

When you create a Cloud Run service through the UI with "Deploy from source", it automatically creates a build trigger that uses a simple Dockerfile build. This trigger needs to be updated to use your custom `cloudbuild.yaml` file instead.

## Verify It's Fixed

After updating, check the trigger configuration:

```bash
gcloud builds triggers describe TRIGGER_NAME
```

You should see `buildConfigFile: cloudbuild.yaml` in the output.

