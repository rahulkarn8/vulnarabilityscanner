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

# Copy startup script
COPY start_server.py /app/start_server.py
RUN chmod +x /app/start_server.py

# Run the application with production settings
# Cloud Run sets PORT environment variable automatically
CMD ["python", "/app/start_server.py"]

