$folder = "C:\ProgramData\POSControl"
$syncScript = "$folder\Download-IntuneScriptsFromGithub.ps1"
$repoRawUrl = "https://raw.githubusercontent.com/thekannen/intune/main/Download-IntuneScriptsFromGithub.ps1"

# Ensure folder exists
if (-not (Test-Path $folder)) {
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
}

# Download the sync script from GitHub
Invoke-WebRequest -Uri $repoRawUrl -OutFile $syncScript -UseBasicParsing

# Create scheduled task to run at user logon
$taskName = "POSControl_ScriptSync"
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$syncScript`""
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\INTERACTIVE" -LogonType Interactive
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force

# Run it once immediately
powershell.exe -ExecutionPolicy Bypass -File $syncScript
