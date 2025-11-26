# Admin Access Setup (Internal Only - No OAuth Required)

The users table and analytics endpoints are now restricted to admin users only using simple API key authentication.

## Configuration

Set **one** of these in your `.env` file (choose either API key OR password):

### Option 1: API Key (Recommended)
```env
ADMIN_API_KEY=your-secret-api-key-here
```

### Option 2: Password
```env
ADMIN_PASSWORD=your-secret-password-here
```

## Protected Endpoints

The following endpoints now require admin access:

- `GET /analytics/users-table` - HTML table view of users
- `GET /analytics/users` - JSON API for users list
- `GET /analytics/usage` - Platform usage statistics
- `GET /analytics/user/{user_id}` - Individual user statistics
- `GET /analytics/summary` - Usage summary

## How to Access

### Method 1: API Key in URL (Easiest for Browser)
```
http://localhost:8000/analytics/users-table?api_key=your-secret-api-key-here
```

### Method 2: API Key in Header (For API calls)
```bash
curl -H "Authorization: Bearer your-secret-api-key-here" \
  http://localhost:8000/analytics/users
```

### Method 3: Password (Basic Auth)
```bash
curl -u admin:your-secret-password-here \
  http://localhost:8000/analytics/users
```

## Security Notes

- **No OAuth required** - Simple internal authentication
- API key or password must match exactly what's in `ADMIN_API_KEY` or `ADMIN_PASSWORD`
- For browser access, use the `?api_key=` query parameter method
- If neither is set, no one can access these endpoints
- Keep your API key/password secure and don't commit it to version control

## Example Setup

```bash
# In backend/.env file:
ADMIN_API_KEY=my-super-secret-key-12345

# Then restart the backend server
# Access via:
# http://localhost:8000/analytics/users-table?api_key=my-super-secret-key-12345
```

## Generate a Secure Key

You can generate a secure random key:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

