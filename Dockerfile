# Use official lightweight Python image
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=5000

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . /app/

# Expose port
EXPOSE 5000

# Run using Gunicorn production WSGI server
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
