# Multi-stage build for Enterprise NGFW API

# Stage 1: Builder
FROM python:3.10-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements/base.txt .
RUN pip install --user --no-cache-dir -r base.txt
RUN pip install --user --no-cache-dir gunicorn uvicorn

# Stage 2: Runtime
FROM python:3.10-slim

WORKDIR /app

# Create non-root user
RUN useradd -m -r ngfwuser && \
    chown ngfwuser:ngfwuser /app

# Copy python dependencies from builder
COPY --from=builder /root/.local /home/ngfwuser/.local

# Copy application code
COPY . .

# Set environment variables
ENV PATH=/home/ngfwuser/.local/bin:$PATH
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Change ownership
RUN chown -R ngfwuser:ngfwuser /app

# Switch to non-root user
USER ngfwuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Command to run (using gunicorn for production)
CMD ["gunicorn", "-c", "api/rest/gunicorn_conf.py", "api.rest.main:app"]
