# Self-healing launcher for SecurePulse.
#
# - Restarts the server automatically if it ever crashes or is killed.
# - Placed in the current user's Startup folder (see install_startup.ps1),
#   so it starts automatically at every logon -- no admin rights required.
# - Backs up the SQLite database once per day before each (re)start, so
#   community patterns and shortened links survive even a corrupted DB file.

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$dbPath      = Join-Path $PSScriptRoot "instance\patterns.db"
$backupDir   = Join-Path $PSScriptRoot "instance\backups"
$logPath     = Join-Path $PSScriptRoot "server.log"
$waitress    = Join-Path $PSScriptRoot "venv\Scripts\waitress-serve.exe"
$maxLogBytes = 5MB
$keepBackups = 30

function Write-Log($message) {
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  $message" | Out-File -FilePath $logPath -Append -Encoding utf8
}

function Backup-Database {
    if (-not (Test-Path $dbPath)) { return }
    New-Item -ItemType Directory -Force -Path $backupDir | Out-Null

    $today = Get-Date -Format "yyyy-MM-dd"
    $target = Join-Path $backupDir "patterns-$today.db"
    if (-not (Test-Path $target)) {
        Copy-Item $dbPath $target
        Write-Log "Backed up database -> $target"
    }

    # Keep only the most recent $keepBackups daily snapshots.
    Get-ChildItem $backupDir -Filter "patterns-*.db" |
        Sort-Object LastWriteTime -Descending |
        Select-Object -Skip $keepBackups |
        Remove-Item -Force
}

function Rotate-Log {
    if ((Test-Path $logPath) -and (Get-Item $logPath).Length -gt $maxLogBytes) {
        $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
        Move-Item $logPath (Join-Path $PSScriptRoot "server-$stamp.log")
    }
}

Write-Log "=== SecurePulse launcher started (PID $PID) ==="

while ($true) {
    Rotate-Log
    Backup-Database

    Write-Log "Starting waitress on 0.0.0.0:5050..."
    & $waitress --listen=0.0.0.0:5050 --threads=8 app:app *>> $logPath
    Write-Log "waitress exited (code $LASTEXITCODE) -- restarting in 5s"

    Start-Sleep -Seconds 5
}
