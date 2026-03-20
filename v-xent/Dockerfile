# Use official Python slim image for a smaller footprint
FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install system dependencies needed for build or execution
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for security
RUN useradd -m vxent_user && chown -R vxent_user /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Ensure output directory exists and is writable by the non-root user
RUN mkdir -p output && chown -R vxent_user:vxent_user /app/output

# Switch to the non-root user
USER vxent_user

# Define the entrypoint and default command
ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
