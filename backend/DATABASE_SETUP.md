# Database Setup Guide

This application supports multiple database backends for different deployment scenarios.

## Supported Databases

1. **SQLite** (Default - Local Development)
2. **PostgreSQL** (Recommended for Cloud/Production)
3. **MySQL/MariaDB** (Alternative for Cloud/Production)

## Configuration

### Local Development (SQLite - Default)

No configuration needed! The app will automatically use SQLite (`auth.db` file).

### Cloud/Production (PostgreSQL or MySQL)

Set the `DATABASE_URL` environment variable:

#### PostgreSQL Example:
```bash
export DATABASE_URL="postgresql://username:password@hostname:5432/dbname"
# Or for PostgreSQL with SSL:
export DATABASE_URL="postgresql://username:password@hostname:5432/dbname?sslmode=require"
```

#### MySQL Example:
```bash
export DATABASE_URL="mysql+pymysql://username:password@hostname:3306/dbname"
```

#### Environment Variable in .env file:
```env
DATABASE_URL=postgresql://user:pass@localhost:5432/vulnerabilityscanner
```

## Cloud Deployment Examples

### AWS (RDS PostgreSQL)
```bash
DATABASE_URL="postgresql://admin:password@your-rds-endpoint.region.rds.amazonaws.com:5432/vulnerabilityscanner"
```

### Google Cloud SQL
```bash
DATABASE_URL="postgresql://user:password@/dbname?host=/cloudsql/project:region:instance"
```

### Heroku
```bash
# Heroku automatically sets DATABASE_URL, just use it
DATABASE_URL=$(heroku config:get DATABASE_URL)
```

### Docker Compose
```yaml
services:
  db:
    image: postgres:15
    environment:
      POSTGRES_USER: scanner
      POSTGRES_PASSWORD: secure_password
      POSTGRES_DB: vulnerabilityscanner
    volumes:
      - postgres_data:/var/lib/postgresql/data

  backend:
    environment:
      DATABASE_URL: postgresql://scanner:secure_password@db:5432/vulnerabilityscanner
```

## Database Drivers

The application automatically detects the database type from the `DATABASE_URL`.

### Required Packages

- **SQLite**: Built into Python (no extra package needed)
- **PostgreSQL**: Requires `psycopg2-binary` (already in requirements.txt)
- **MySQL**: Requires `pymysql` (already in requirements.txt)

## Automatic Migrations

The application automatically:
1. Creates all required tables on first run
2. Adds missing columns (like `expires_at` and `usage_logs` table)
3. Handles database-specific syntax differences

## Database Schema

The application uses the following tables:
- `users` - User accounts and authentication
- `scan_counts` - Scan limit tracking
- `usage_logs` - Platform usage analytics
- `learned_vulnerabilities` - ML-learned vulnerability patterns

## Troubleshooting

### Connection Issues
- Ensure the database server is running and accessible
- Check firewall rules allow connections
- Verify credentials in `DATABASE_URL`

### Migration Errors
- Check database user has CREATE TABLE permissions
- For existing databases, ensure tables don't already exist
- Review logs for specific error messages

### Performance
- PostgreSQL/MySQL are recommended for production
- SQLite is fine for development but not suitable for production
- Consider connection pooling for high-traffic deployments

