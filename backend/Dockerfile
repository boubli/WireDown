FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code
COPY . .

# Expose HTTP Hub (5000), Fake SSH (2222), and DNS Sinkhole (5353 UDP)
EXPOSE 5000
EXPOSE 2222
EXPOSE 5353/udp

CMD ["python", "app.py"]
