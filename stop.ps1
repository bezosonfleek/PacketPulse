# ──────────────────────────────────────────────────────────────
#  PacketPulse — Windows Stop Script
#
#  Stops all PacketPulse services:
#  1. Kills the native Python backend process
#  2. Stops Docker containers (db + frontend)
#
#  Usage:
#    Right-click stop.ps1 → Run with PowerShell
#    OR in terminal: .\stop.ps1
# ──────────────────────────────────────────────────────────────

$ROOT = $PSScriptRoot

Write-Host ""
Write-Host "  Stopping PacketPulse..." -ForegroundColor Yellow

# ── Stop native backend ───────────────────────────────────────
Write-Host "  Stopping backend..." -ForegroundColor Yellow
Get-Process python -ErrorAction SilentlyContinue | Where-Object {
    $_.MainWindowTitle -like "*PacketPulse*" -or $_.CommandLine -like "*main.py*"
} | Stop-Process -Force -ErrorAction SilentlyContinue

# Fallback — kill any python process running main.py
$procs = Get-WmiObject Win32_Process -Filter "Name='python.exe'" |
    Where-Object { $_.CommandLine -like "*main.py*" }
foreach ($p in $procs) {
    Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
}

Write-Host "  Backend stopped." -ForegroundColor Green

# ── Stop Docker containers ────────────────────────────────────
Write-Host "  Stopping Docker containers..." -ForegroundColor Yellow
Set-Location $ROOT
docker-compose down 2>&1 | Out-Null

Write-Host "  Docker stopped." -ForegroundColor Green
Write-Host ""
Write-Host "  PacketPulse stopped." -ForegroundColor Cyan
Write-Host ""
