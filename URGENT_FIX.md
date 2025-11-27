# URGENT: Fix Cloud Build Trigger

## The Problem
Your build is still using the default Dockerfile build instead of `cloudbuild.yaml`. This happens when the trigger was created through Cloud Run's UI.

## Solution: Update the Trigger Configuration

### Step 1: Find Your Trigger

Run this command to see all triggers:

```bash
gcloud builds triggers list --format="table(id,name,github.owner,github.name,buildConfigFile)"
```

Look for a trigger related to `vulnarabilityscanner`. Note the trigger ID or name.

### Step 2: Update the Trigger

**If you see the trigger in the list:**

```bash
# Replace TRIGGER_ID with the actual ID from step 1
gcloud builds triggers update TRIGGER_ID \
    --build-config=cloudbuild.yaml
```

**If the trigger doesn't appear or update fails:**

The trigger might be managed by Cloud Run. In this case:

1. **Go to Cloud Run Console**: https://console.cloud.google.com/run
2. **Find your service** (if any exist)
3. **Delete the service** (this will also remove its build trigger)
4. **Create a new trigger manually**:

```bash
gcloud builds triggers create github \
    --repo-name=vulnarabilityscanner \
    --repo-owner=rahulkarn8 \
    --branch-pattern="^main$" \
    --build-config=cloudbuild.yaml \
    --name=vulnerability-scanner-build
```

### Step 3: Alternative - Delete All Triggers and Recreate

If nothing works, start fresh:

```bash
# List all triggers
gcloud builds triggers list

# Delete ALL triggers for this repo (be careful!)
gcloud builds triggers delete TRIGGER_ID_1
gcloud builds triggers delete TRIGGER_ID_2
# ... delete all of them

# Create a clean new trigger
gcloud builds triggers create github \
    --repo-name=vulnarabilityscanner \
    --repo-owner=rahulkarn8 \
    --branch-pattern="^main$" \
    --build-config=cloudbuild.yaml \
    --name=vulnerability-scanner-build
```

### Step 4: Verify

After updating, verify the trigger:

```bash
gcloud builds triggers describe vulnerability-scanner-build
```

You should see `buildConfigFile: cloudbuild.yaml` in the output.

### Step 5: Test

Push a commit or manually trigger:

```bash
gcloud builds triggers run vulnerability-scanner-build --branch=main
```

## Why This Keeps Happening

Cloud Run's "Deploy from source" feature creates a special build trigger that's hard to update. The trigger is configured to look for a `Dockerfile` in the root, which doesn't exist in your project structure.

Your project needs `cloudbuild.yaml` because:
- Backend Dockerfile is in `backend/Dockerfile`
- Frontend Dockerfile is in `frontend/Dockerfile`
- You need to build both services
- You need custom build contexts

## Quick Test Without Trigger

To test if `cloudbuild.yaml` works, submit a build manually:

```bash
gcloud builds submit --config=cloudbuild.yaml .
```

If this works, the issue is definitely the trigger configuration.

