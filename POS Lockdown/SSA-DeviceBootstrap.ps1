# Pushed from NinjaOne - Device Bootstrapper

$basePath = "C:\ProgramData\SSA"
$logFilePath = "$basePath\Logs\BootstrapperLog.txt"
$folders = @("Scripts", "Secrets", "Logs")

# --- Logging function ---
function Write-Log {
    param([string]$Message)

    $logFolder = Split-Path $logFilePath
    if (-not (Test-Path $logFolder)) {
        New-Item -Path $logFolder -ItemType Directory -Force | Out-Null
    }

    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "$timestamp - $Message" | Out-File -FilePath $logFilePath -Append -Encoding utf8
}


# Create required directories
foreach ($folder in $folders) {
    $fullPath = Join-Path $basePath $folder
    if (-Not (Test-Path $fullPath)) {
        New-Item -Path $fullPath -ItemType Directory -Force
        Write-Log "Created folder: $fullPath"
    } else {
        Write-Log "Folder already exists: $fullPath"
    }
}

# Set Permissions (Restrictive but readable by users for Scripts and Secrets)
try {
    icacls "$basePath\Secrets" /inheritance:r
    icacls "$basePath\Secrets" /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Authenticated Users:(OI)(CI)RX"
    Write-Log "Set ACLs for Secrets folder."

    icacls "$basePath\Scripts" /inheritance:r
    icacls "$basePath\Scripts" /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Authenticated Users:(OI)(CI)RX"
    Write-Log "Set ACLs for Scripts folder."
} catch {
    Write-Log "ERROR setting folder permissions: $($_.Exception.Message)"
}

# Create a secret file
#----------- !!REPLACE CLIENT SECRET AT TIME OF SCRIPT INSTALL!! ---------------
$clientSecret = 'YOUR-GRAPH-API-CLIENT-SECRET'
try {
    Set-Content -Path "$basePath\Secrets\GraphApiCred.txt" -Value $clientSecret -Force
    Write-Log "Client secret file created successfully."
} catch {
    Write-Log "ERROR creating client secret file: $($_.Exception.Message)"
}

# Download and create the Download-ScriptsFromGithub.ps1
$downloadScript = @"
# Downloads updated scripts from GitHub
\$RepoURL = 'https://raw.githubusercontent.com/thekannen/intune/main/POS%20Lockdown/'
\$ScriptList = 'scripts.json'

\$localScriptPath = '$basePath\Scripts'
\$localScriptJson = Join-Path \$localScriptPath 'scripts.json'

# Download the scripts.json first
Invoke-WebRequest -Uri "\$RepoURL\$ScriptList" -OutFile \$localScriptJson -UseBasicParsing

# Parse and download each script listed
\$scripts = (Get-Content -Path \$localScriptJson | ConvertFrom-Json).scripts
foreach (\$script in \$scripts) {
    \$scriptUrl = "\$RepoURL\$script"
    Invoke-WebRequest -Uri \$scriptUrl -OutFile (Join-Path \$localScriptPath \$script) -UseBasicParsing
}
"@
try {
    Set-Content -Path "$basePath\Scripts\Download-ScriptsFromGithub.ps1" -Value $downloadScript -Force
    Write-Log "Download-ScriptsFromGithub.ps1 script created successfully."
} catch {
    Write-Log "ERROR creating Download-ScriptsFromGithub.ps1: $($_.Exception.Message)"
}

# Create Scheduled Task (Run at Logon as USER)
try {
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$basePath\Scripts\POSLockdown.ps1`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users" -RunLevel Limited
    Register-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -TaskName "SSA_POSLockdown" -Description "Enforces device lockdown based on Azure group" -Force
    Write-Log "Scheduled Task SSA_POSLockdown created successfully."
} catch {
    Write-Log "ERROR creating SSA_POSLockdown task: $($_.Exception.Message)"
}

# Create Scheduled Task for Script Auto-Update
try {
    $updateAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$basePath\Scripts\Download-ScriptsFromGithub.ps1`""
    $updateTrigger = New-ScheduledTaskTrigger -Daily -At 3am
    $updatePrincipal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users" -RunLevel Limited
    Register-ScheduledTask -Action $updateAction -Trigger $updateTrigger -Principal $updatePrincipal -TaskName "SSA_ScriptUpdater" -Description "Updates SSA scripts nightly" -Force
    Write-Log "Scheduled Task SSA_ScriptUpdater created successfully."
} catch {
    Write-Log "ERROR creating SSA_ScriptUpdater task: $($_.Exception.Message)"
}

# Initial Script Pull (download scripts.json + scripts)
try {
    Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$basePath\Scripts\Download-ScriptsFromGithub.ps1`"" -Wait
    Write-Log "Initial script download started successfully."
} catch {
    Write-Log "ERROR starting initial script download: $($_.Exception.Message)"
}

# Final message
Write-Log "SSA System setup complete."
