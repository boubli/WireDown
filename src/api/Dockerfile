FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY src/api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code (both API and UI templates/assets are needed)
COPY src /app/src

# Set working directory to the API folder
WORKDIR /app/src/api

# Expose HTTP Hub (5000), Fake SSH (2222), and DNS Sinkhole (5353 UDP)
EXPOSE 5000
EXPOSE 2222
EXPOSE 5353/udp

# Run the unified ASGI server entrypoint
CMD ["python", "server.py"]

