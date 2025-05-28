# Intune Control Scheduled Task Setup
# Description:
#   - Downloads Intune-controlled scripts from GitHub to C:\ProgramData\IntuneControl
#   - Sets up a scheduled task SYSTEM-level task that syncs scripts from GitHub at startup
$folder = "C:\ProgramData\IntuneControl"
$syncScript = "$folder\Download-IntuneScriptsFromGithub.ps1"
$repoRawUrl = "https://raw.githubusercontent.com/thekannen/intune/main/Download-IntuneScriptsFromGithub.ps1"

# Ensure the local folder exists
if (-not (Test-Path $folder)) {
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
}

# Download the sync script from GitHub
Invoke-WebRequest -Uri $repoRawUrl -OutFile $syncScript -UseBasicParsing

# --- SYSTEM TASK: Sync scripts from GitHub at startup ---

$startupTaskName  = "IntuneControl_ScriptDownloader"
$startupScript    = $syncScript
$startupAction    = New-ScheduledTaskAction -Execute "powershell.exe" `
                     -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$startupScript`""
$startupTrigger   = New-ScheduledTaskTrigger -AtStartup
$startupPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$startupSettings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName $startupTaskName `
    -Action $startupAction `
    -Trigger $startupTrigger `
    -Principal $startupPrincipal `
    -Settings $startupSettings `
    -Force

# Run it immediately to ensure the scripts are pulled down at least once
powershell.exe -ExecutionPolicy Bypass -File $syncScript