# Fix Cloud Build Configuration

If you're seeing errors like:
```
unable to prepare context: unable to evaluate symlinks in Dockerfile path: lstat /workspace/Dockerfile: no such file or directory
```

This means Cloud Build is not using your `cloudbuild.yaml` file. Here's how to fix it:

## Option 1: Update Existing Build Trigger

1. Go to [Cloud Build Triggers](https://console.cloud.google.com/cloud-build/triggers)
2. Find your trigger for the repository
3. Click "Edit"
4. Under "Configuration", select "Cloud Build configuration file (yaml or json)"
5. Set the location to: `cloudbuild.yaml`
6. Save the trigger

## Option 2: Create New Build Trigger

```bash
# Set your project
export PROJECT_ID="your-project-id"
export REGION="us-central1"

# Create a new trigger that uses cloudbuild.yaml
gcloud builds triggers create github \
    --repo-name=vulnarabilityscanner \
    --repo-owner=rahulkarn8 \
    --branch-pattern="^main$" \
    --build-config=cloudbuild.yaml \
    --name=vulnerability-scanner-build \
    --project=$PROJECT_ID
```

## Option 3: Manually Submit Build

If you want to test the build immediately:

```bash
# Submit build manually with explicit config
gcloud builds submit --config=cloudbuild.yaml .
```

## Option 4: Delete and Recreate Trigger

If the above doesn't work:

```bash
# List existing triggers
gcloud builds triggers list

# Delete the problematic trigger
gcloud builds triggers delete TRIGGER_NAME

# Create a new one with correct config
gcloud builds triggers create github \
    --repo-name=vulnarabilityscanner \
    --repo-owner=rahulkarn8 \
    --branch-pattern="^main$" \
    --build-config=cloudbuild.yaml \
    --name=vulnerability-scanner-build
```

## Verify Configuration

After updating, verify the trigger uses the correct config:

```bash
# Describe the trigger
gcloud builds triggers describe TRIGGER_NAME

# Look for "buildConfigFile: cloudbuild.yaml" in the output
```

## Common Issues

1. **Trigger using "Dockerfile" instead of "cloudbuild.yaml"**: 
   - The trigger was created through Cloud Run UI, which uses automatic builds
   - Solution: Update the trigger to use `cloudbuild.yaml` as shown above

2. **Build context issues**:
   - The `cloudbuild.yaml` is already configured with correct build contexts (`backend` and `frontend`)
   - Make sure the file is in the repository root

3. **Substitution variables not set**:
   - Update the trigger to include substitution variables, or
   - Set them in the Cloud Build UI under "Substitution variables"

