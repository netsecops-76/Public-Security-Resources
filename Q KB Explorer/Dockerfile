FROM python:3.12-slim

LABEL maintainer="netsecops-76"
LABEL description="Q KB Explorer - Qualys Knowledge Base & Policy Compliance"

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app/ ./app/
COPY entrypoint.sh .

# Bake build version (git commit SHA) into the image
ARG BUILD_VERSION=dev
RUN echo "${BUILD_VERSION}" > /app/.current_version
RUN chmod +x entrypoint.sh

# Create certs directory (mount point for TLS)
RUN mkdir -p /app/certs

# Create credential vault mount points (separate volumes for security)
# /keys — holds .vault_key.bin (AES-256 encryption key, hidden, 0400)
# /data — holds vault.json (encrypted credentials, 0600) + qkbe.db (SQLite)
RUN mkdir -p /keys /data && chmod 700 /keys /data
VOLUME ["/keys", "/data"]

# Expose port
EXPOSE 5000

# Entrypoint with TLS auto-detection
ENTRYPOINT ["./entrypoint.sh"]
