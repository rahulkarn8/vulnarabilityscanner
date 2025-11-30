FROM python:3.13-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create directory for database
RUN mkdir -p /app/data

# Expose port (Cloud Run uses PORT env var, default to 8000)
EXPOSE ${PORT:-8000}

# Run the application with production settings
# Cloud Run sets PORT environment variable automatically
# Use a simple startup script that handles PORT correctly
RUN echo '#!/bin/bash\nset -e\nPORT=${PORT:-8000}\necho "Starting server on port $PORT"\nexec uvicorn main:app --host 0.0.0.0 --port "$PORT" --workers 1 --timeout-keep-alive 30' > /app/start.sh && chmod +x /app/start.sh

CMD ["/app/start.sh"]

