# Use the official Python slim image for a lightweight footprint
FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080

# Set the working directory inside the container
WORKDIR /app

# Copy dependency configuration files, readme, and source
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install build dependencies and project packages
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir hatchling && \
    pip install --no-cache-dir .

# Expose port 8080 (documentation only; Cloud Run overrides this dynamically)
EXPOSE 8080

# Start FastAPI application using uvicorn, binding to the dynamic Cloud Run PORT
CMD exec uvicorn src.main:app --host 0.0.0.0 --port ${PORT}
