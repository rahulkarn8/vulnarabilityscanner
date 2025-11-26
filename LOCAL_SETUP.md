# Local Development Setup Guide

This guide explains how to run the application locally for development.

## Prerequisites

- Python 3.13+ installed
- Node.js 20+ and npm installed
- Git installed

## Quick Start

### 1. Backend Setup

```bash
# Navigate to backend directory
cd backend

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
# venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment file template
cp .env.local.example .env

# Edit .env file with your OAuth credentials
# Make sure to set ENVIRONMENT=development
nano .env  # or use your preferred editor

# Start backend server
python main.py
```

The backend will run on `http://localhost:8000`

### 2. Frontend Setup

Open a new terminal:

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Optional: Copy environment file (uses localhost by default in dev mode)
cp .env.local.example .env.local

# Start frontend development server
npm run dev
```

The frontend will run on `http://localhost:3000` (or the next available port)

### 3. Access the Application

- Frontend: `http://localhost:3000` or `http://localhost:5173`
- Backend API: `http://localhost:8000`
- API Docs: `http://localhost:8000/docs`

## Environment Variables

### Backend (.env)

Key variables for local development:

```env
ENVIRONMENT=development
GITHUB_REDIRECT_URI=http://localhost:8000/auth/github/callback
GOOGLE_REDIRECT_URI=http://localhost:8000/auth/google/callback
FRONTEND_URL=http://localhost:5173
```

### Frontend (.env.local)

The frontend automatically detects development mode and uses `http://localhost:8000` by default.

To override, create `.env.local`:
```env
VITE_API_URL=http://localhost:8000
```

## OAuth Setup for Local Development

### GitHub OAuth

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Create a new OAuth App
3. Set:
   - **Homepage URL**: `http://localhost:5173`
   - **Authorization callback URL**: `http://localhost:8000/auth/github/callback`
4. Copy Client ID and Secret to your `.env` file

### Google OAuth

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create OAuth client ID
3. Add authorized redirect URI: `http://localhost:8000/auth/google/callback`
4. Copy Client ID and Secret to your `.env` file

## Running Both Servers

### Option 1: Manual (Two Terminals)

Terminal 1:
```bash
cd backend
source venv/bin/activate
python main.py
```

Terminal 2:
```bash
cd frontend
npm run dev
```

### Option 2: Using the Start Script

```bash
# From project root
chmod +x start.sh
./start.sh
```

## Troubleshooting

### Backend Issues

1. **Port 8000 already in use:**
   ```bash
   lsof -ti:8000 | xargs kill -9
   ```

2. **Module not found errors:**
   ```bash
   cd backend
   source venv/bin/activate
   pip install -r requirements.txt
   ```

### Frontend Issues

1. **Port 3000/5173 already in use:**
   - Vite will automatically try the next available port

2. **API connection errors:**
   - Ensure backend is running on port 8000
   - Check that `VITE_API_URL` in `.env.local` matches your backend URL

### OAuth Issues

1. **Redirect URI mismatch:**
   - Ensure redirect URIs in OAuth app settings match exactly
   - Check `.env` file has correct redirect URIs

2. **CORS errors:**
   - Backend should automatically allow `localhost` origins in development
   - Check backend CORS settings in `main.py`

## Development vs Production

The application automatically detects the environment:

- **Development**: Uses `localhost:8000` for API calls
- **Production**: Uses `codescanner.daifend.ai` domain

Detection is based on:
- Frontend: `window.location.hostname` or `import.meta.env.DEV`
- Backend: `ENVIRONMENT=development` or `DEBUG=true` in `.env`

## Database

The SQLite database (`auth.db`) is created automatically in the backend directory when you first run the server. It will persist between restarts.

## Hot Reload

- Frontend: Vite provides hot module replacement (HMR)
- Backend: Restart required for code changes (consider using `uvicorn --reload`)

To enable auto-reload for backend:
```bash
cd backend
source venv/bin/activate
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

