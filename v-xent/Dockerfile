# Stage 1: Build dependencies
FROM python:3.10-slim AS builder

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    libffi-dev \
    libpangocairo-1.0-0 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Stage 2: Final hardened image
FROM python:3.10-slim

WORKDIR /app

# Install only runtime dependencies (needed for weasyprint/pdf)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpangocairo-1.0-0 \
    libharfbuzz0b \
    libpango-1.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root system user
RUN groupadd -r vxent && useradd -r -g vxent -s /sbin/nologin vxent_user

# Copy installed python packages from builder
COPY --from=builder /root/.local /home/vxent_user/.local
ENV PATH=/home/vxent_user/.local/bin:$PATH

# Copy application code
COPY . .

# Set up output directory with correct permissions
RUN mkdir -p output && chown -R vxent_user:vxent /app/output

# Task 4: Hardening measures
# Ensure the user has access to their local bin
USER vxent_user

# Environment variables (to be overridden by compose/secrets)
ENV SHODAN_API_KEY=""
ENV VT_API_KEY=""

ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
