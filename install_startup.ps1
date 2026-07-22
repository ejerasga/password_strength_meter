# One-time setup: makes SecurePulse start automatically (hidden) whenever
# this user logs into Windows, and keep restarting itself if it ever
# crashes. Needs no admin rights -- it only touches this user's own
# Startup folder.
#
# Run once:   powershell -ExecutionPolicy Bypass -File install_startup.ps1
# Undo:       powershell -ExecutionPolicy Bypass -File install_startup.ps1 -Uninstall

param(
    [switch]$Uninstall
)

$startupDir = [Environment]::GetFolderPath("Startup")
$target = Join-Path $startupDir "SecurePulse.vbs"

if ($Uninstall) {
    if (Test-Path $target) {
        Remove-Item $target -Force
        Write-Output "Removed $target -- SecurePulse will no longer start automatically at logon."
    } else {
        Write-Output "Nothing to remove -- SecurePulse wasn't installed to start at logon."
    }
    return
}

Copy-Item -Path (Join-Path $PSScriptRoot "run_server_hidden.vbs") -Destination $target -Force
Write-Output "Installed: $target"
Write-Output "SecurePulse will now start automatically (hidden) the next time you log in,"
Write-Output "and will restart itself within 5 seconds if it ever crashes."
Write-Output ""
Write-Output "To start it right now without logging out, run:"
Write-Output "  wscript.exe `"$target`""
