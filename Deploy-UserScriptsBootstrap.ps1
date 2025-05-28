# Deploy-UserScriptsBootstrap.ps1
# Description:
#   - Creates a scheduled task that runs at user logon
#   - Task runs the user-context script: Run-UserScriptsFromGithubManifest.ps1
#   - Intended to be deployed via Intune with "Run script as logged-on user" = YES

# Constants
$folder = "C:\ProgramData\IntuneControl"
$scriptPath = Join-Path $folder "Run-UserScriptsFromGithubManifest.ps1"
$taskName = "IntuneControl_RunUserScripts"

# Ensure the folder exists
if (-not (Test-Path $folder)) {
    New-Item -Path $folder -ItemType Directory -Force | Out-Null
}

# Ensure the script exists (optional: placeholder)
if (-not (Test-Path $scriptPath)) {
    Set-Content -Path $scriptPath -Value "# Placeholder script to be overwritten by downloader." -Force
}

# Build task action
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""

# Trigger on every user logon
$trigger = New-ScheduledTaskTrigger -AtLogOn

# Use the current user context
$currentUser = "$env:USERDOMAIN\$env:USERNAME"
$principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Limited

# Basic task settings
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -MultipleInstances IgnoreNew

# Register the task
try {
    Register-ScheduledTask -TaskName $taskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Force

    Write-Host "Scheduled task '$taskName' created successfully for user $currentUser."
} catch {
    Write-Error "Failed to create scheduled task: $_"
}
