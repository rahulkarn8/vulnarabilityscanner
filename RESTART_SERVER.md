# Restart Backend Server

If you're seeing "backend server is not running" error, follow these steps:

## Quick Restart

1. **Stop the current server:**
   ```bash
   # Find and kill the process on port 8000
   lsof -ti:8000 | xargs kill -9
   ```

2. **Restart the backend:**
   ```bash
   cd backend
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   python main.py
   ```

   Or use the start script from project root:
   ```bash
   ./start.sh
   ```

## Verify Server is Running

Test if the server is responding:
```bash
curl http://localhost:8000/
```

You should see:
```json
{"message":"Code Vulnerability Dashboard API",...}
```

## Common Issues

### 1. Port Already in Use
If port 8000 is already in use:
```bash
# Find what's using port 8000
lsof -ti:8000

# Kill it
lsof -ti:8000 | xargs kill -9
```

### 2. Virtual Environment Not Activated
Make sure you're using the virtual environment:
```bash
cd backend
source venv/bin/activate  # On Windows: venv\Scripts\activate
python main.py
```

### 3. Database Connection Issues
If you see database errors:
- For SQLite (default): Make sure `backend/auth.db` file exists or can be created
- For PostgreSQL/MySQL: Check your `DATABASE_URL` environment variable

### 4. Frontend Can't Connect
- Check that backend is running on `http://localhost:8000`
- Check browser console for CORS errors
- Verify `frontend/src/config.ts` has correct `API_URL`

## Using Docker

If using Docker Compose:
```bash
docker-compose restart backend
```

Or rebuild:
```bash
docker-compose down
docker-compose up -d
```

