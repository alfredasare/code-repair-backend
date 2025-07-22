# Use Python 3.12 slim image as base
FROM python:3.12-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Install system dependencies and uv
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN pip install uv

# Create a non-root user
RUN useradd --create-home --shell /bin/bash app

# Set work directory and change ownership
WORKDIR /app
RUN chown app:app /app

# Switch to non-root user early
USER app

# Copy uv files as app user
COPY --chown=app:app pyproject.toml uv.lock ./

# Install dependencies using uv as app user
RUN uv sync --frozen --no-cache

# Copy application code as app user (excluding .venv via .dockerignore)
COPY --chown=app:app . .

# Expose port
EXPOSE 8000

# Command to run the application
CMD ["uv", "run", "fastapi", "run", "main.py", "--host", "0.0.0.0", "--port", "8000"]