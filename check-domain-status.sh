#!/bin/bash

# Script to check domain mapping status and show DNS records

set -e

# Configuration
PROJECT_ID="${GCP_PROJECT_ID:-avian-bricolage-475907-f8}"
REGION="${GCP_REGION:-europe-west1}"
DOMAIN="${CUSTOM_DOMAIN:-stratum.daifend.ai}"

echo "🔍 Checking domain mapping status for: $DOMAIN"
echo ""

# Check domain mapping status
echo "📊 Domain Mapping Details:"
gcloud beta run domain-mappings describe \
    --domain="$DOMAIN" \
    --region="$REGION" \
    --project="$PROJECT_ID" \
    --format="yaml"

echo ""
echo "📋 DNS Records (if status is not ACTIVE, add these to your DNS provider):"
gcloud beta run domain-mappings describe \
    --domain="$DOMAIN" \
    --region="$REGION" \
    --project="$PROJECT_ID" \
    --format="value(status.resourceRecords)" || echo "No DNS records found or domain is already active"

