# MCP Proxy Server Dockerfile

# Use official Python image
FROM python:3-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/

# Create non-root user for security
RUN useradd -m -u 1000 proxyuser && \
    chown -R proxyuser:proxyuser /app

# Switch to non-root user
USER proxyuser

# Expose port (default: 8000)
EXPOSE 8000

# Set default environment variables
# BEARER_TOKEN intentionally has no default; the app will refuse to start
# without one. Set it at runtime via environment or .env file.
ENV PROXY_HOST=127.0.0.1 \
    PROXY_PORT=8000 \
    TARGET_MCP_URL=http://localhost:8080 \
    DEBUG=false

# Run the application
CMD ["python", "-m", "src.main"]

# Alternative: Use uvicorn directly
# CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
