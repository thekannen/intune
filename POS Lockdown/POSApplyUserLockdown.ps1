# ------------------------------
# POSApplyUserLockdown.ps1
# ------------------------------
# SYSTEM-context script that applies lockdown or clears it
# based on per-user SID cache written by the user login script.
# ------------------------------

# --- CONFIGURABLE LOCKDOWN SETTINGS ---
$LockdownOptions = @{
    # Disables "Shut down", "Restart", "Sleep", etc. in Start menu
    NoClose = $true

    # Blocks Control Panel and Settings app (also blocks Network UI)
    NoControlPanel = $true

    # Add more registry options below if needed:
    # "SomeOtherPolicyName" = $true/false
}

# --- PATH SETUP ---
$queuePath = "C:\ProgramData\SSA\LockdownQueue"
$logPath   = "C:\ProgramData\SSA\Logs\POSLockdownSystem.log"

# --- Logging function (standardized) ---
function Write-Log {
    param([string]$Message)

    $logFolder = Split-Path $logPath
    if (-not (Test-Path $logFolder)) {
        New-Item -Path $logFolder -ItemType Directory -Force | Out-Null
    }

    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "$timestamp - $Message" | Out-File -FilePath $logPath -Append -Encoding utf8
}

# --- PROCESS EACH USER POLICY DECISION ---
Get-ChildItem -Path $queuePath -Filter "*.txt" -ErrorAction SilentlyContinue | ForEach-Object {
    $sid = $_.BaseName
    $decision = Get-Content $_.FullName -ErrorAction SilentlyContinue | Select-Object -First 1
    $regPath = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

    try {
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }

        if ($decision -eq "LOCKDOWN") {
            foreach ($setting in $LockdownOptions.GetEnumerator()) {
                if ($setting.Value) {
                    try {
                        Set-ItemProperty -Path $regPath -Name $setting.Key -Value 1 -Type DWord -Force
                        Write-Log "[INFO] [$sid] Applied: $($setting.Key)=1"
                    } catch {
                        Write-Log "[ERROR] [$sid] Failed to apply $($setting.Key): $($_.Exception.Message)"
                    }
                }
            }
            Write-Log "[INFO] [$sid] Lockdown applied."
        }
        else {
            foreach ($setting in $LockdownOptions.Keys) {
                try {
                    Remove-ItemProperty -Path $regPath -Name $setting -ErrorAction SilentlyContinue
                    Write-Log "[INFO] [$sid] Removed: $setting"
                } catch {
                    Write-Log "[WARN] [$sid] Failed to remove $setting: $($_.Exception.Message)"
                }
            }
            Write-Log "[INFO] [$sid] Lockdown removed (status: $decision)."
        }

        Write-Log "[INFO] [$sid] Lockdown decision processed and retained for caching."
    }
    catch {
        Write-Log "[ERROR] [$sid] General failure: $($_.Exception.Message)"
    }
}
