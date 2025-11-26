# Restart Backend Server

The backend server needs to be restarted to load the new email/password authentication endpoints.

## Quick Restart

If running directly with Python:
```bash
# Stop the current server (Ctrl+C in the terminal where it's running)
# Then restart:
cd backend
python main.py
# or
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

If running with Docker:
```bash
docker-compose restart backend
# or
docker-compose up -d --build backend
```

## Verify Routes Are Loaded

After restarting, check that the routes are available:
```bash
curl http://localhost:8000/openapi.json | grep -o '"/auth/[^"]*"'
```

You should see:
- `/auth/register`
- `/auth/login`

## Install Missing Dependency

Make sure `email-validator` is installed:
```bash
cd backend
pip install email-validator
```

Or install all requirements:
```bash
pip install -r requirements.txt
```

