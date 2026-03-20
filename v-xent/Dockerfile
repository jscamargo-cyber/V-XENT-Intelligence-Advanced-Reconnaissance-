# Base image
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create output directory
RUN mkdir -p output

# Environment variables placeholder
ENV SHODAN_API_KEY=""
ENV VT_API_KEY=""

# Entry point
ENTRYPOINT ["python", "main.py"]

# Default command help
CMD ["--help"]
