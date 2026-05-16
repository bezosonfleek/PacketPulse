# ──────────────────────────────────────────────────────────────
#  PacketPulse — Windows Startup Script
#
#  Architecture:
#    db       — Docker (Postgres)
#    frontend — Docker (Nginx)
#    backend  — Native Windows Python
#
#  The backend runs natively so it uses your real Windows
#  network stack and can scan your physical network.
#
#  Usage:
#    Right-click start.ps1 -> Run with PowerShell
#    OR in terminal: .\start.ps1
# ──────────────────────────────────────────────────────────────

$ROOT        = $PSScriptRoot
$VENV_PYTHON = "$ROOT\.venv\Scripts\python.exe"
$BACKEND     = "$ROOT\backend\main.py"
$APP_URL     = "http://localhost:3000"

Write-Host ""
Write-Host "  PacketPulse Network Scanner" -ForegroundColor Cyan
Write-Host "  Starting services..." -ForegroundColor DarkGray
Write-Host ""

# ── Check prerequisites ───────────────────────────────────────
if (-not (Test-Path $VENV_PYTHON)) {
    Write-Host "  [ERROR] Python venv not found." -ForegroundColor Red
    Write-Host "  Run: python -m venv .venv" -ForegroundColor Yellow
    Write-Host "       .venv\Scripts\pip install -r backend\requirements.txt" -ForegroundColor Yellow
    pause
    exit 1
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "  [ERROR] Docker not found. Is Docker Desktop running?" -ForegroundColor Red
    pause
    exit 1
}

# ── Update .env for native backend ───────────────────────────
# Native backend connects to db via localhost:5433
$envFile = "$ROOT\.env"
if (Test-Path $envFile) {
    $envContent = Get-Content $envFile
    $envContent = $envContent -replace "^DB_HOST=.*", "DB_HOST=localhost"
    $envContent = $envContent -replace "^DB_PORT=.*", "DB_PORT=5433"
    $envContent | Set-Content $envFile
}

# ── Start Docker (db + frontend) ─────────────────────────────
Write-Host "  [1/3] Starting Docker services (db + frontend)..." -ForegroundColor Yellow
Set-Location $ROOT
docker-compose up -d 2>&1 | Out-Null

# ── Wait for db healthcheck ───────────────────────────────────
Write-Host "  [2/3] Waiting for database..." -ForegroundColor Yellow
$attempts = 0
do {
    Start-Sleep -Seconds 2
    $attempts++
    $health = docker inspect packetpulse-db-1 --format "{{.State.Health.Status}}" 2>$null
    if ($attempts -gt 30) {
        Write-Host "  [ERROR] Database did not become healthy in time." -ForegroundColor Red
        pause
        exit 1
    }
} while ($health -ne "healthy")
Write-Host "  [2/3] Database ready." -ForegroundColor Green

# ── Start backend natively ────────────────────────────────────
Write-Host "  [3/3] Starting backend on Windows network stack..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-Command",
    "Write-Host 'PacketPulse Backend' -ForegroundColor Cyan; cd '$ROOT'; & '$VENV_PYTHON' '$BACKEND'"
) -WindowStyle Normal

Start-Sleep -Seconds 3

# ── Done ─────────────────────────────────────────────────────
Write-Host ""
Write-Host "  Ready at: $APP_URL" -ForegroundColor Green
Write-Host "  Backend logs are in the other terminal window." -ForegroundColor DarkGray
Write-Host "  Run .\stop.ps1 to shut everything down." -ForegroundColor DarkGray
Write-Host ""
Start-Process $APP_URL