# Authentication Setup Guide

This guide will help you set up GitHub and Google OAuth authentication for the vulnerability scanner application.

## Backend Setup

### 1. Install Dependencies

Make sure all authentication dependencies are installed:

```bash
cd backend
pip install -r requirements.txt
```

### 2. Environment Variables

Create a `.env` file in the `backend` directory with the following variables:

```env
# JWT Secret Key (generate a secure random string)
# You can generate one using: python -c "import secrets; print(secrets.token_urlsafe(32))"
JWT_SECRET_KEY=your-secret-key-here

# GitHub OAuth Configuration
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
GITHUB_REDIRECT_URI=http://localhost:8000/auth/github/callback

# Google OAuth Configuration
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/auth/google/callback

# Frontend URL
FRONTEND_URL=http://localhost:5173

# OpenAI API Key (optional, for enhanced suggestions)
OPENAI_API_KEY=your-openai-api-key-here
```

### 3. GitHub OAuth Setup

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Fill in the application details:
   - **Application name**: Vulnerability Scanner (or any name)
   - **Homepage URL**: `http://localhost:5173`
   - **Authorization callback URL**: `http://localhost:8000/auth/github/callback`
4. Click "Register application"
5. Copy the **Client ID** and **Client Secret**
6. Add them to your `.env` file

### 4. Google OAuth Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Navigate to **APIs & Services** > **Credentials**
4. Click **Create Credentials** > **OAuth client ID**
5. If prompted, configure the OAuth consent screen:
   - User Type: External
   - Fill in required fields (App name, User support email, Developer contact)
   - Add scopes: `email`, `profile`, `openid`
6. Create OAuth client ID:
   - Application type: **Web application**
   - Name: Vulnerability Scanner (or any name)
   - **Authorized JavaScript origins**: `http://localhost:5173`
   - **Authorized redirect URIs**: `http://localhost:8000/auth/google/callback`
7. Click "Create"
8. Copy the **Client ID** and **Client Secret**
9. Add them to your `.env` file

### 5. Generate JWT Secret Key

Generate a secure JWT secret key:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Copy the output and add it to your `.env` file as `JWT_SECRET_KEY`.

### 6. Start the Backend Server

```bash
cd backend
python main.py
```

The backend will automatically create the SQLite database (`auth.db`) for storing user information on first run.

## Frontend Setup

No additional configuration is needed for the frontend. The authentication UI is already integrated.

Just make sure the frontend is running on `http://localhost:5173` (or update `FRONTEND_URL` in the backend `.env` if using a different port).

## Testing Authentication

1. Start both backend and frontend servers
2. Navigate to `http://localhost:5173`
3. You should see a login page with GitHub and Google login buttons
4. Click on either button to authenticate
5. After successful authentication, you'll be redirected back to the dashboard
6. You should see your user information in the header

## Troubleshooting

### "OAuth not configured" error

- Make sure all OAuth credentials are correctly set in the `.env` file
- Check that there are no typos in the environment variable names
- Restart the backend server after updating `.env`

### Redirect URI mismatch

- Ensure the redirect URIs in your OAuth app settings match exactly what's in your `.env` file
- For GitHub: `http://localhost:8000/auth/github/callback`
- For Google: `http://localhost:8000/auth/google/callback`

### Frontend can't reach backend

- Make sure the backend is running on port 8000
- Check CORS settings in `backend/main.py` if running frontend on a different port
- Verify `FRONTEND_URL` in `.env` matches your frontend URL

### Database errors

- The SQLite database (`auth.db`) will be created automatically
- If you encounter database errors, you can delete `auth.db` and restart the server
- Make sure SQLAlchemy is properly installed: `pip install sqlalchemy==2.0.23`

## Production Deployment

For production deployment:

1. Use a strong, randomly generated `JWT_SECRET_KEY`
2. Update all redirect URIs to use your production domain
3. Use environment variables or a secure secrets management system
4. Consider using PostgreSQL instead of SQLite for the database
5. Enable HTTPS for all OAuth redirect URIs
6. Update CORS settings to only allow your production frontend domain

