# PacketPulse — Docker Deployment

## Prerequisites - * Application is still in testing phase and I can't assure reliability
- Docker Desktop installed (includes both docker & docker-compose)
- Git

## First-time setup

### 1. Copy and fill in environment variables
```bash
cp .env.example .env
```
Open `.env` and set at minimum:
- `DB_PASSWORD` — any strong password
- `JWT_SECRET` — generate with: `python -c "import secrets; print(secrets.token_hex(48))"`

### 2. Build and start all containers
```bash
docker-compose up --build
```
What this does:
- Builds the backend image from `backend/Dockerfile`
- Builds the frontend image from `frontend/Dockerfile`
- Pulls the `postgres:15-alpine` image from Docker Hub
- Creates the `packetpulse-net` network
- Creates the `postgres-data` volume
- Starts all three containers in the correct order
- Streams all logs to your terminal

### 3. Open the app
```
http://localhost:3000
```

---

## Daily usage

### Start (background)
```bash
docker-compose up -d
```
The `-d` flag runs containers in detached mode (background).

### Stop
```bash
docker-compose down
```
Stops and removes containers. Your Postgres data is safe in the volume.

### View logs
```bash
docker-compose logs -f           # all services
docker-compose logs -f backend   # backend only
docker-compose logs -f frontend  # nginx only
docker-compose logs -f db        # postgres only
```

### Rebuild after code changes
```bash
docker-compose up --build
```
Docker only rebuilds layers that changed. If you only changed
Python files, pip install is skipped (cached layer).

---

## Useful Docker commands

```bash
# List running containers
docker ps

# Open a shell inside the backend container
docker-compose exec backend bash

# Open psql directly in the database
docker-compose exec db psql -U pp_user -d packetpulse

# Wipe everything including the database volume (destructive)
docker-compose down -v
```

---

## Moving to production (cloud server)

1. Copy the project to your server via `git clone` or `scp`
2. Update `.env`:
   - `ALLOWED_ORIGIN=https://yourdomain.com`
   - `APP_BASE_URL=https://yourdomain.com`
   - Strong `DB_PASSWORD` and `JWT_SECRET`
3. Change `docker-compose.yml` ports to `"80:80"`
4. Point your domain's A record to the server IP
5. Add SSL with Certbot:
   ```bash
   apt install certbot python3-certbot-nginx
   certbot --nginx -d yourdomain.com
   ```
