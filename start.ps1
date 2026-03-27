$ROOT = $PSScriptRoot
$VENV_PYTHON = "$ROOT\.venv\Scripts\python.exe"
$BACKEND = "$ROOT\backend\main.py"
$APP_URL = "http://localhost:3000"

Write-Host ""
Write-Host "  PacketPulse Network Scanner" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path $VENV_PYTHON)) {
    Write-Host "  [ERROR] Python venv not found at: $VENV_PYTHON" -ForegroundColor Red
    Write-Host "  Run: python -m venv .venv && .venv\Scripts\pip install -r backend\requirements.txt" -ForegroundColor Yellow
    pause
    exit 1
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "  [ERROR] Docker not found. Is Docker Desktop running?" -ForegroundColor Red
    pause
    exit 1
}

Write-Host "  [1/3] Starting Docker services (db + frontend)..." -ForegroundColor Yellow
Set-Location $ROOT
docker-compose up -d 2>&1 | Out-Null

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

Write-Host "  [3/3] Starting backend (native Windows - scans your physical network)..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-Command",
    "cd '$ROOT'; Write-Host 'PacketPulse Backend' -ForegroundColor Cyan; & '$VENV_PYTHON' '$BACKEND'"
) -WindowStyle Normal

Start-Sleep -Seconds 3

Write-Host ""
Write-Host "  PacketPulse is running at: $APP_URL" -ForegroundColor Green
Write-Host "  Backend logs are in the other terminal window." -ForegroundColor DarkGray
Write-Host "  Run .\stop.ps1 to shut everything down." -ForegroundColor DarkGray
Write-Host ""
Start-Process $APP_URL