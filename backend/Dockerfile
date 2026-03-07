# ──────────────────────────────────────────────────────────────
#  PacketPulse — Backend Dockerfile
#
#  What this file does, line by line:
#
#  FROM      — choose a base image. python:3.11-slim is the
#              official Python image but stripped of extras,
#              keeping the final image small (~150MB vs ~1GB).
#
#  WORKDIR   — sets the working directory inside the container.
#              All subsequent commands run from /app.
#
#  COPY requirements.txt — copy ONLY requirements first.
#              Docker builds in layers. If requirements.txt
#              hasn't changed, Docker uses the cached layer
#              and skips pip install entirely. Much faster
#              rebuilds when you only change app code.
#
#  RUN pip   — install Python dependencies inside the container.
#              --no-cache-dir keeps the image smaller.
#
#  COPY .    — copy all backend source files into /app.
#              Done AFTER pip so the pip layer stays cached.
#
#  EXPOSE    — documents that the container listens on 8000.
#              This is informational — actual port mapping
#              happens in docker-compose.yml.
#
#  CMD       — the command that runs when the container starts.
#              Using ["python", "-u", "main.py"] — the -u flag
#              disables output buffering so logs appear
#              immediately in docker logs.
# ──────────────────────────────────────────────────────────────

FROM python:3.11-slim

# Set working directory inside the container
WORKDIR /app

# Copy requirements first — maximises Docker layer cache hits
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy all backend source files
COPY . .

# Document the port this service listens on
EXPOSE 8000

# Start the backend server
# -u = unbuffered output so logs stream immediately
CMD ["python", "-u", "main.py"]