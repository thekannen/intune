# Pushed from NinjaOne - Device Bootstrapper

$basePath = "C:\ProgramData\SSA"
$logFilePath = "$basePath\Logs\BootstrapperLog.txt"
$folders = @("Scripts", "Secrets", "Logs", "LockdownQueue")

#----------- !!REPLACE CLIENT SECRET AT TIME OF SCRIPT INSTALL!! ---------------
$clientSecretPlain = '!!REPLACE_WITH_CLIENT_SECRET!!'

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
    icacls "$basePath\Secrets" /grant:r "Authenticated Users:(OI)(CI)(RX)" 

    # Scripts - Read-only for users
    icacls "$basePath\Scripts" /inheritance:r
    icacls "$basePath\Scripts" /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Authenticated Users:(OI)(CI)(RX)"

    # Logs - Writable by users
    icacls "$basePath\Logs" /inheritance:r
    icacls "$basePath\Logs" /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Authenticated Users:(OI)(CI)(M)"

    # LockdownQueue - Allow write for all users
    $queuePath = "$basePath\LockdownQueue"
    if (-not (Test-Path $queuePath)) {
        New-Item -Path $queuePath -ItemType Directory -Force | Out-Null
        Write-Log "Created folder: $queuePath"
    }

    # Remove inherited permissions and assign explicit ACLs
    icacls $queuePath /inheritance:r
    icacls $queuePath /grant:r `
        "SYSTEM:(OI)(CI)F" `
        "Administrators:(OI)(CI)F" `
        "Authenticated Users:(OI)(CI)(M)"

} catch {
    Write-Log "ERROR setting folder permissions: $($_.Exception.Message)"
}

# Create a secret file (encrypted for all users on this machine)
try {
    Add-Type -AssemblyName System.Security
    $plain = [System.Text.Encoding]::UTF8.GetBytes($clientSecretPlain)
    $encrypted = [System.Security.Cryptography.ProtectedData]::Protect($plain, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    [Convert]::ToBase64String($encrypted) | Out-File "$basePath\Secrets\GraphApiCred.dat"
    Write-Log "Client secret encrypted with machine scope."

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

# Create Schedule Task to detect and cache logged in user (Run at Logon as USER)
try {
    $userAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\ProgramData\SSA\Scripts\POSUserPolicyDetector.ps1"'
    $userTrigger = New-ScheduledTaskTrigger -AtLogOn
    $userPrincipal = New-ScheduledTaskPrincipal -GroupId "Users" -RunLevel Limited

    Register-ScheduledTask -TaskName "SSA - Detect POS Lockdown (User)" `
        -Action $userAction `
        -Trigger $userTrigger `
        -Principal $userPrincipal `
        -Description "Detects user lockdown group membership at logon" `
        -Force
} catch {
    Write-Log "ERROR creating SSA - Detect POS Lockdown (User) task: $($_.Exception.Message)"
}

# Create Scheduled Task to apply the settings (Run at Logon as SYSTEM with 5s delay)
try {
    $sysAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\ProgramData\SSA\Scripts\POSApplyUserLockdown.ps1"'
    $sysTrigger = New-ScheduledTaskTrigger -AtLogOn
    $sysTrigger.Delay = 'PT5S'  # 5-second delay to let user script finish first

    Register-ScheduledTask -TaskName "SSA - Apply POS Lockdown (System)" `
        -Action $sysAction `
        -Trigger $sysTrigger `
        -RunLevel Highest `
        -User "SYSTEM" `
        -Force
} catch {
    Write-Log "ERROR creating SSA - Apply POS Lockdown (System) task: $($_.Exception.Message)"
}

# Create Scheduled Task for Script Auto-Update at logon with 5-minute delay
try {
    $updateAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$localDownloadScriptPath`""
    $updateTrigger = New-ScheduledTaskTrigger -AtLogOn
    $updateTrigger.Delay = 'PT5M'  # Delay 5 minutes after logon

    $updatePrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask -Action $updateAction `
        -Trigger $updateTrigger `
        -Principal $updatePrincipal `
        -TaskName "SSA_ScriptUpdater" `
        -Description "Updates SSA scripts after logon" `
        -Force

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

# Start tasks to set permissions immediately
Start-ScheduledTask -TaskName "SSA - Detect POS Lockdown (User)"
Start-ScheduledTask -TaskName "SSA - Apply POS Lockdown (System)"

Write-Log "POS Lockdown tasks complete"

# Final message
Write-Log "SSA System setup complete."
