' Launches run_server.ps1 with no visible console window.
' A copy of this file in the Startup folder makes SecurePulse start
' automatically at every logon -- see install_startup.ps1.
Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
psScript = scriptDir & "\run_server.ps1"

cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & psScript & """"
CreateObject("WScript.Shell").Run cmd, 0, False
