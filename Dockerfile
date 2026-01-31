# Use a lightweight Python base
FROM python:3.11-slim

# 1. Install system network tools required for scanning
# We need 'net-tools' for ARP and 'iputils-ping' for OS detection
RUN apt-get update && apt-get install -y \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# 2. Set the internal container directory
WORKDIR /app

# 3. Copy your app files into the container
COPY . .

# 4. Open the port your Python script uses
EXPOSE 8000

# 5. Run the script (unbuffered -u to see logs instantly)
CMD ["python", "-u", "demo.py"]

