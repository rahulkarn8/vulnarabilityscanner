#!/usr/bin/env python3
"""
Startup script for Cloud Run
Reads PORT from environment and starts uvicorn server
"""
import os
import sys

# Get PORT from environment, default to 8000
port = int(os.environ.get('PORT', 8000))
host = '0.0.0.0'

print(f"Starting server on {host}:{port}")
print(f"Python version: {sys.version}")
print(f"Working directory: {os.getcwd()}")

# Import and run uvicorn
import uvicorn

try:
    uvicorn.run(
        'main:app',
        host=host,
        port=port,
        workers=1,
        timeout_keep_alive=30,
        log_level='info'
    )
except Exception as e:
    print(f"Error starting server: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

