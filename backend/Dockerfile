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
# Use Python to read PORT from environment
CMD python -c "import os; import uvicorn; port = int(os.environ.get('PORT', 8000)); uvicorn.run('main:app', host='0.0.0.0', port=port, workers=1)"

