# Docker Deployment Guide

This guide explains how to deploy the Code Scanner application using Docker.

## Prerequisites

- Docker and Docker Compose installed
- Domain name `codescanner.daifend.ai` configured to point to your server

## Quick Start

1. **Set up environment variables:**

   Copy `.env.example` to `.env` and fill in your values:
   ```bash
   cp .env.example .env
   nano .env
   ```

2. **Build and start containers:**
   ```bash
   docker-compose up -d --build
   ```

3. **Check status:**
   ```bash
   docker-compose ps
   ```

## Configuration

### OAuth Setup

Make sure your OAuth applications (GitHub and Google) are configured with:

- **GitHub OAuth:**
  - Authorization callback URL: `https://codescanner.daifend.ai/auth/github/callback`

- **Google OAuth:**
  - Authorized redirect URIs: `https://codescanner.daifend.ai/auth/google/callback`

### Environment Variables

The application uses environment variables from the `.env` file. Key variables:

- `JWT_SECRET_KEY`: Secret key for JWT token generation
- `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET`: GitHub OAuth credentials
- `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`: Google OAuth credentials
- `FRONTEND_URL`: Auto-set to `https://codescanner.daifend.ai`
- `GITHUB_REDIRECT_URI`: Auto-set to `https://codescanner.daifend.ai/auth/github/callback`
- `GOOGLE_REDIRECT_URI`: Auto-set to `https://codescanner.daifend.ai/auth/google/callback`

## Services

- **Backend**: FastAPI application running on port 8000
- **Frontend**: Nginx serving React app on port 80

## SSL/HTTPS Setup

For production, you should set up HTTPS using a reverse proxy (like Nginx or Traefik) with SSL certificates (Let's Encrypt recommended).

Example with Nginx reverse proxy:

```nginx
server {
    listen 443 ssl http2;
    server_name codescanner.daifend.ai;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Useful Commands

- **View logs:**
  ```bash
  docker-compose logs -f backend
  docker-compose logs -f frontend
  ```

- **Stop containers:**
  ```bash
  docker-compose down
  ```

- **Restart containers:**
  ```bash
  docker-compose restart
  ```

- **Rebuild after changes:**
  ```bash
  docker-compose up -d --build
  ```

## Troubleshooting

1. **Port conflicts:** Make sure ports 80 and 8000 are not in use
2. **Database issues:** The database is stored in `./backend/auth.db` as a volume
3. **OAuth errors:** Verify redirect URIs match exactly in OAuth app settings

