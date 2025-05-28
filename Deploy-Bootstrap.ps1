$folder = "C:\ProgramData\POSControl"
$syncScript = "$folder\Download-GitHubScripts.ps1"
$repoUrl = "https://raw.githubusercontent.com/<org>/pos-powershell-scripts/main/Download-GitHubScripts.ps1"

# Ensure folder exists
if (-not (Test-Path $folder)) {
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
}

# Download the sync script from GitHub (public or private w/token logic)
Invoke-WebRequest -Uri $repoUrl -OutFile $syncScript -UseBasicParsing

# Create scheduled task to run at user logon
$taskName = "POSControl_ScriptSync"
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$syncScript`""
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\INTERACTIVE" -LogonType Interactive
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force

# Run it once immediately
powershell.exe -ExecutionPolicy Bypass -File $syncScript
