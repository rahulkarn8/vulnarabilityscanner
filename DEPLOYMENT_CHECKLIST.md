# Quick Deployment Checklist

## Pre-Deployment

- [ ] Create `.env` file in project root
- [ ] Set `DATABASE_URL` to your existing database (PostgreSQL/MySQL)
- [ ] Generate and set `JWT_SECRET_KEY`
- [ ] Configure GitHub OAuth credentials
- [ ] Configure Google OAuth credentials
- [ ] Set up Stripe payment keys (if using payments)
- [ ] Configure support email SMTP settings (if using support page)
- [ ] Set admin credentials (if using admin endpoints)

## Deployment Steps

1. **Create `.env` file** with all required variables (see PRODUCTION_DEPLOYMENT.md)

2. **Deploy using Docker Compose:**
   ```bash
   docker-compose up -d --build
   ```

   Or use the deployment script:
   ```bash
   ./deploy.sh
   ```

3. **Verify services are running:**
   ```bash
   docker-compose ps
   docker-compose logs -f
   ```

4. **Test the application:**
   - Frontend: https://codescanner.daifend.ai
   - Backend API: https://codescanner.daifend.ai/api/docs
   - Test login (GitHub, Google, Email/Password)
   - Test scanning functionality

## Post-Deployment

- [ ] Verify database connection is working
- [ ] Test OAuth logins (GitHub, Google)
- [ ] Test email/password registration and login
- [ ] Test file scanning
- [ ] Test compliance report generation
- [ ] Test support email functionality
- [ ] Set up SSL certificate (if not already done)
- [ ] Configure firewall rules
- [ ] Set up monitoring/logging
- [ ] Configure automatic backups for database

## Environment Variables Required

```env
DATABASE_URL=your_existing_database_url
JWT_SECRET_KEY=your_jwt_secret
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
FRONTEND_URL=https://codescanner.daifend.ai
```

## Troubleshooting

- **Check logs**: `docker-compose logs -f backend`
- **Restart services**: `docker-compose restart`
- **Rebuild**: `docker-compose up -d --build`
- **Check database connection**: Verify DATABASE_URL is correct and accessible

