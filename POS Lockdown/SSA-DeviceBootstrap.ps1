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
   # Secrets - No user access
    icacls "$basePath\Secrets" /inheritance:r
    icacls "$basePath\Secrets" /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F"

    # Scripts - Read-only for users
    icacls "$basePath\Scripts" /inheritance:r
    icacls "$basePath\Scripts" /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Authenticated Users:(OI)(CI)(RX)"

    # Logs - Writable by users
    icacls "$basePath\Logs" /inheritance:r
    icacls "$basePath\Logs" /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Authenticated Users:(OI)(CI)(M)"

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

# Download Download-ScriptsFromGithub.ps1 only
try {
    $downloadScriptURL = 'https://raw.githubusercontent.com/thekannen/intune/main/POS%20Lockdown/Download-ScriptsFromGithub.ps1'
    $localDownloadScriptPath = Join-Path $basePath "Scripts\Download-ScriptsFromGithub.ps1"
    
    Invoke-WebRequest -Uri $downloadScriptURL -OutFile $localDownloadScriptPath -UseBasicParsing -ErrorAction Stop
    Write-Log "Download-ScriptsFromGithub.ps1 downloaded successfully."
} catch {
    Write-Log "ERROR downloading Download-ScriptsFromGithub.ps1: $($_.Exception.Message)"
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
    $updateAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$localDownloadScriptPath`""
    $updateTrigger = New-ScheduledTaskTrigger -Daily -At 3am
    $updatePrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -Action $updateAction -Trigger $updateTrigger -Principal $updatePrincipal -TaskName "SSA_ScriptUpdater" -Description "Updates SSA scripts nightly" -Force
    Write-Log "Scheduled Task SSA_ScriptUpdater created successfully."
} catch {
    Write-Log "ERROR creating SSA_ScriptUpdater task: $($_.Exception.Message)"
}

# Initial Script Pull (Download-ScriptsFromGithub.ps1 kicks off the rest)
try {
    Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$localDownloadScriptPath`"" -Wait
    Write-Log "Initial script download started successfully."
} catch {
    Write-Log "ERROR starting initial script download: $($_.Exception.Message)"
}

# Final message
Write-Log "SSA System setup complete."
