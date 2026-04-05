FROM python:3.11-slim

# Install scanning tools and system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    nikto \
    gobuster \
    curl \
    dnsutils \
    net-tools \
    iputils-ping \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps (slim list, not full pip freeze)
COPY requirements.docker.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create non-root user
RUN useradd -m -s /bin/bash redteam && chown -R redteam:redteam /app

EXPOSE 8001

# Health check
HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
    CMD curl -sf http://localhost:8001/api/ || exit 1

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8001", "--workers", "1"]
