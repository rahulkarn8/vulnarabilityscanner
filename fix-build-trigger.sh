#!/bin/bash

# Script to fix Cloud Build trigger to use cloudbuild.yaml
# This script will help you identify and fix the build trigger issue

set -e

echo "🔍 Checking Cloud Build triggers..."
echo ""

# List all triggers
echo "Current Cloud Build triggers:"
gcloud builds triggers list --format="table(id,name,github.owner,github.name,buildConfigFile)" || echo "No triggers found or not authenticated"

echo ""
echo "📋 To fix the build trigger, you have two options:"
echo ""
echo "OPTION 1: Update via Google Cloud Console (Recommended)"
echo "1. Go to: https://console.cloud.google.com/cloud-build/triggers"
echo "2. Find your trigger for 'vulnarabilityscanner'"
echo "3. Click 'Edit'"
echo "4. Under 'Configuration', change from 'Dockerfile' to 'Cloud Build configuration file (yaml or json)'"
echo "5. Set the location to: cloudbuild.yaml"
echo "6. Click 'Save'"
echo ""
echo "OPTION 2: Update via Command Line"
echo "Run these commands (replace TRIGGER_NAME with your actual trigger name):"
echo ""
echo "  # List triggers to find the name"
echo "  gcloud builds triggers list"
echo ""
echo "  # Update the trigger"
echo "  gcloud builds triggers update TRIGGER_NAME \\"
echo "      --build-config=cloudbuild.yaml"
echo ""
echo "OPTION 3: Delete and Recreate (if update doesn't work)"
echo ""
echo "  # Delete the old trigger"
echo "  gcloud builds triggers delete TRIGGER_NAME"
echo ""
echo "  # Create new trigger with correct config"
echo "  gcloud builds triggers create github \\"
echo "      --repo-name=vulnarabilityscanner \\"
echo "      --repo-owner=rahulkarn8 \\"
echo "      --branch-pattern='^main$' \\"
echo "      --build-config=cloudbuild.yaml \\"
echo "      --name=vulnerability-scanner-build"
echo ""

