# Setting Up Custom Domain for Cloud Run

This guide will help you map `stratum.daifend.ai` to your Cloud Run services.

## Prerequisites

- You own `daifend.ai` domain
- Your domain DNS is managed by a DNS provider (Google Domains, Cloudflare, Route53, etc.)
- You have access to your DNS provider's control panel

## Step 1: Map Domain to Frontend Service

```bash
# Set your variables
export PROJECT_ID="avian-bricolage-475907-f8"
export REGION="europe-west1"
export FRONTEND_SERVICE="vulnerability-scanner-frontend"
export DOMAIN="stratum.daifend.ai"

# Map the domain to your frontend Cloud Run service
gcloud run domain-mappings create \
    --service "$FRONTEND_SERVICE" \
    --domain "$DOMAIN" \
    --region "$REGION" \
    --project="$PROJECT_ID"
```

This command will output DNS records that you need to add to your DNS provider.

## Step 2: Add DNS Records

After running the command above, you'll see output like:

```
Waiting for domain mapping to be created...done.
Please add the following entries to your DNS provider:
  Type: A
  Name: stratum
  Data: 216.239.32.21
  Type: A
  Name: stratum
  Data: 216.239.36.21
  ...
  Type: CNAME
  Name: stratum
  Data: ghs.googlehosted.com
```

### Option A: Using A Records (Recommended)

Add **A records** to your DNS provider:

1. Go to your DNS provider's control panel (where you manage `daifend.ai`)
2. Add A records for `stratum` subdomain:
   - **Type**: A
   - **Name/Host**: `stratum` (or `stratum.daifend.ai` depending on your provider)
   - **Value/Points to**: The IP addresses provided by Cloud Run (usually 4-6 IPs)
   - **TTL**: 3600 (or default)

### Option B: Using CNAME (Alternative)

Some providers prefer CNAME:
- **Type**: CNAME
- **Name**: `stratum`
- **Value**: `ghs.googlehosted.com` (or the value provided by Cloud Run)

## Step 3: Verify DNS Propagation

Wait for DNS to propagate (usually 5-30 minutes, can take up to 48 hours):

```bash
# Check if DNS records are propagated
dig stratum.daifend.ai
# or
nslookup stratum.daifend.ai
```

## Step 4: Verify Domain Mapping

```bash
# Check the status of your domain mapping
gcloud run domain-mappings describe "$DOMAIN" \
    --region="$REGION" \
    --project="$PROJECT_ID"
```

Wait until the status shows `ACTIVE` and `READY` is `True`.

## Step 5: Update Backend CORS Configuration

Once the domain is active, update your backend to allow requests from the custom domain:

```bash
# Get your backend service name
export BACKEND_SERVICE="vulnerability-scanner-backend"

# Update CORS_ORIGINS to include the custom domain
gcloud run services update "$BACKEND_SERVICE" \
    --update-env-vars "CORS_ORIGINS=https://stratum.daifend.ai" \
    --region="$REGION" \
    --project="$PROJECT_ID"
```

Or update both FRONTEND_URL and CORS_ORIGINS:

```bash
gcloud run services update "$BACKEND_SERVICE" \
    --update-env-vars "FRONTEND_URL=https://stratum.daifend.ai,CORS_ORIGINS=https://stratum.daifend.ai" \
    --region="$REGION" \
    --project="$PROJECT_ID"
```

## Step 6: Test the Domain

Once DNS has propagated and the domain mapping is active:

```bash
# Test if the domain is accessible
curl -I https://stratum.daifend.ai
```

You should see HTTP 200 or 301/302 redirects.

## Common DNS Providers

### Google Domains / Google Cloud DNS

1. Go to [Google Domains](https://domains.google.com) or [Cloud DNS](https://console.cloud.google.com/net-services/dns)
2. Select your domain `daifend.ai`
3. Go to DNS settings
4. Add A records with the IPs provided by Cloud Run

### Cloudflare

1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Select your domain `daifend.ai`
3. Go to DNS → Records
4. Add A records (Cloudflare will proxy automatically, which is fine)

### Route53 (AWS)

1. Go to [Route53 Console](https://console.aws.amazon.com/route53)
2. Select your hosted zone for `daifend.ai`
3. Create A records with the IPs provided

### Other Providers

The process is similar:
1. Find DNS management section
2. Add A records for `stratum` subdomain
3. Use the IP addresses provided by Cloud Run

## Troubleshooting

### Domain mapping stuck in "PENDING" status

- Check that DNS records are correctly added
- Verify DNS propagation: `dig stratum.daifend.ai`
- Wait up to 48 hours for full propagation

### SSL Certificate Issues

Cloud Run automatically provisions SSL certificates via Let's Encrypt. This can take a few minutes to a few hours after DNS is verified.

### CORS Errors

Make sure you've updated `CORS_ORIGINS` in your backend service to include `https://stratum.daifend.ai`.

### Check Domain Mapping Status

```bash
gcloud run domain-mappings list \
    --region="$REGION" \
    --project="$PROJECT_ID"
```

## Optional: Map Backend to Subdomain

If you want to expose the backend API directly (optional):

```bash
# Map backend to api.stratum.daifend.ai (or api.daifend.ai)
gcloud run domain-mappings create \
    --service "$BACKEND_SERVICE" \
    --domain "api.stratum.daifend.ai" \
    --region "$REGION" \
    --project="$PROJECT_ID"
```

Then add the corresponding DNS records.

## Quick Setup Script

Here's a complete script to set up the domain:

```bash
#!/bin/bash
set -e

export PROJECT_ID="avian-bricolage-475907-f8"
export REGION="europe-west1"
export FRONTEND_SERVICE="vulnerability-scanner-frontend"
export BACKEND_SERVICE="vulnerability-scanner-backend"
export DOMAIN="stratum.daifend.ai"

echo "🌐 Setting up custom domain: $DOMAIN"

# Step 1: Create domain mapping
echo "📋 Creating domain mapping..."
gcloud run domain-mappings create \
    --service "$FRONTEND_SERVICE" \
    --domain "$DOMAIN" \
    --region "$REGION" \
    --project="$PROJECT_ID"

echo ""
echo "✅ Domain mapping created!"
echo ""
echo "📝 Next steps:"
echo "1. Add the DNS records shown above to your DNS provider"
echo "2. Wait for DNS propagation (5-30 minutes)"
echo "3. Run: gcloud run domain-mappings describe $DOMAIN --region=$REGION --project=$PROJECT_ID"
echo "4. Once active, update backend CORS with the script below"
```

## After Domain is Active

Once the domain is verified and active, update your deployment script to use the custom domain instead of Cloud Run URLs.

