#!/bin/bash

# Script to check and fix Cloud Build trigger
# This will list triggers and help you identify which one to update

set -e

PROJECT_ID="${GCP_PROJECT_ID:-avian-bricolage-475907-f8}"
REGION="${GCP_REGION:-europe-west1}"

echo "🔍 Checking Cloud Build triggers for project: $PROJECT_ID"
echo ""

# List all triggers
echo "📋 Current Cloud Build triggers:"
echo "----------------------------------------"
gcloud builds triggers list --project="$PROJECT_ID" --format="table(id,name,github.owner,github.name,buildConfigFile,filename)" || {
    echo "❌ Error: Could not list triggers. Make sure you're authenticated:"
    echo "   gcloud auth login"
    exit 1
}

echo ""
echo "🔧 To fix the trigger, run one of these commands:"
echo ""
echo "OPTION 1: Update existing trigger (recommended)"
echo "----------------------------------------"
echo "First, identify the trigger ID or name from the list above, then run:"
echo ""
echo "  gcloud builds triggers update TRIGGER_ID \\"
echo "      --build-config=cloudbuild.yaml \\"
echo "      --project=$PROJECT_ID"
echo ""
echo "OPTION 2: Create a new trigger"
echo "----------------------------------------"
echo "  gcloud builds triggers create github \\"
echo "      --repo-name=vulnarabilityscanner \\"
echo "      --repo-owner=rahulkarn8 \\"
echo "      --branch-pattern='^main$' \\"
echo "      --build-config=cloudbuild.yaml \\"
echo "      --name=vulnerability-scanner-build \\"
echo "      --project=$PROJECT_ID"
echo ""
echo "OPTION 3: Delete old trigger and create new one"
echo "----------------------------------------"
echo "  # List triggers to find the problematic one"
echo "  gcloud builds triggers list --project=$PROJECT_ID"
echo ""
echo "  # Delete it"
echo "  gcloud builds triggers delete TRIGGER_ID --project=$PROJECT_ID"
echo ""
echo "  # Create new one"
echo "  gcloud builds triggers create github \\"
echo "      --repo-name=vulnarabilityscanner \\"
echo "      --repo-owner=rahulkarn8 \\"
echo "      --branch-pattern='^main$' \\"
echo "      --build-config=cloudbuild.yaml \\"
echo "      --name=vulnerability-scanner-build \\"
echo "      --project=$PROJECT_ID"
echo ""

