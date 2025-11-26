# Production Deployment Guide

This guide will help you deploy the Daifend Vulnerability Scanner to production while keeping your existing database URL.

## Prerequisites

- Docker and Docker Compose installed
- Your existing database URL (PostgreSQL/MySQL)
- Domain name configured (codescanner.daifend.ai)
- SSL certificate (Let's Encrypt recommended)

## Step 1: Environment Variables

Create a `.env` file in the project root with the following variables:

```env
# Database (use your existing database URL)
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

# OpenAI API (optional, for AI suggestions)
OPENAI_API_KEY=your_openai_api_key

# Stripe (for payments)
STRIPE_SECRET_KEY=your_stripe_secret_key
STRIPE_PRICE_ID_BASIC=price_id_for_basic_plan
STRIPE_PRICE_ID_PRO=price_id_for_pro_plan

# Admin Access (optional, for internal admin endpoints)
ADMIN_API_KEY=your_secure_admin_api_key
ADMIN_PASSWORD=your_secure_admin_password

# Support Email (for support page)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password
FROM_EMAIL=your_email@gmail.com
SUPPORT_EMAIL=support@daifend.com

# Scan Limits (for unpaid users)
FREE_SCAN_LIMIT=5
```

### Generating JWT Secret Key

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

### Getting GitHub OAuth Credentials

1. Go to GitHub Settings → Developer settings → OAuth Apps
2. Create a new OAuth App
3. Set Authorization callback URL to: `https://codescanner.daifend.ai/auth/github/callback`
4. Copy Client ID and Client Secret

### Getting Google OAuth Credentials

1. Go to Google Cloud Console → APIs & Services → Credentials
2. Create OAuth 2.0 Client ID
3. Set Authorized redirect URI to: `https://codescanner.daifend.ai/auth/google/callback`
4. Copy Client ID and Client Secret

### Setting up Gmail for Support Emails

1. Enable 2-Factor Authentication on your Google account
2. Generate an App Password: Google Account → Security → 2-Step Verification → App passwords
3. Use this app password as `SMTP_PASSWORD`

## Step 2: Update OAuth Redirect URIs

Make sure your OAuth providers have the correct production redirect URIs:

- **GitHub**: `https://codescanner.daifend.ai/auth/github/callback`
- **Google**: `https://codescanner.daifend.ai/auth/google/callback`

## Step 3: Build and Deploy

### Option A: Using Docker Compose (Recommended)

```bash
# Build and start services
docker-compose up -d --build

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Option B: Manual Docker Build

```bash
# Build backend
cd backend
docker build -t codescanner-backend .
cd ..

# Build frontend
cd frontend
docker build -t codescanner-frontend .
cd ..

# Run containers
docker run -d \
  --name codescanner-backend \
  -p 8000:8000 \
  --env-file ../.env \
  codescanner-backend

docker run -d \
  --name codescanner-frontend \
  -p 80:80 \
  codescanner-frontend
```

## Step 4: Configure Reverse Proxy (Nginx)

If you're using a reverse proxy (recommended), configure it to:

1. **Frontend** (port 80): Serve static files and proxy API requests
2. **Backend** (port 8000): Handle API requests

Example Nginx configuration:

```nginx
server {
    listen 80;
    server_name codescanner.daifend.ai;

    # Frontend
    location / {
        proxy_pass http://localhost:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Backend API
    location /api/ {
        proxy_pass http://localhost:8000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket support (if needed)
    location /ws/ {
        proxy_pass http://localhost:8000/ws/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

## Step 5: SSL Certificate (Let's Encrypt)

```bash
# Install certbot
sudo apt-get update
sudo apt-get install certbot python3-certbot-nginx

# Get certificate
sudo certbot --nginx -d codescanner.daifend.ai

# Auto-renewal (already configured by certbot)
```

## Step 6: Verify Deployment

1. **Check Backend**: `https://codescanner.daifend.ai/api/docs` (FastAPI docs)
2. **Check Frontend**: `https://codescanner.daifend.ai`
3. **Test Login**: Try GitHub, Google, and email/password login
4. **Test Scanning**: Upload a file or scan a directory
5. **Test Support**: Send a test email from the support page

## Step 7: Monitoring and Maintenance

### View Logs

```bash
# All services
docker-compose logs -f

# Backend only
docker-compose logs -f backend

# Frontend only
docker-compose logs -f frontend
```

### Update Application

```bash
# Pull latest code
git pull

# Rebuild and restart
docker-compose up -d --build
```

### Database Backups

Since you're using an external database, ensure you have regular backups configured through your database provider.

## Troubleshooting

### Backend Not Starting

1. Check logs: `docker-compose logs backend`
2. Verify DATABASE_URL is correct
3. Ensure database is accessible from the server
4. Check JWT_SECRET_KEY is set

### Frontend Not Loading

1. Check logs: `docker-compose logs frontend`
2. Verify API_URL in browser console
3. Check nginx configuration
4. Ensure backend is running

### OAuth Not Working

1. Verify redirect URIs match exactly
2. Check OAuth credentials in .env
3. Ensure FRONTEND_URL is set correctly
4. Check browser console for errors

### Database Connection Issues

1. Verify DATABASE_URL format
2. Check database is accessible from server
3. Ensure firewall allows connections
4. Verify credentials are correct

## Security Checklist

- [ ] JWT_SECRET_KEY is strong and random
- [ ] Database credentials are secure
- [ ] OAuth secrets are protected
- [ ] Admin credentials are set (if using admin endpoints)
- [ ] SSL certificate is installed and auto-renewing
- [ ] Environment variables are not committed to git
- [ ] Firewall is configured (only ports 80, 443, and 8000 if needed)
- [ ] Regular database backups are configured

## Support

For issues or questions, contact support@daifend.com or check the support page in the application.

