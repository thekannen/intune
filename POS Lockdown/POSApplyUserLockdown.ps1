# ------------------------------
# POSApplyUserLockdown.ps1
# ------------------------------
# This script is intended to run at SYSTEM context after user logon.
# It reads each user's decision cache (from LockdownQueue) and applies lockdown policies (from LockdownMatrix.json)
# for each user based on their company (unit) and role/jobtitle.
# Policies are applied by setting or removing registry keys in the user's registry hive.

$queuePath      = "C:\ProgramData\SSA\LockdownQueue"               # Folder holding decision JSON for each user SID
$matrixPath     = "C:\ProgramData\SSA\Scripts\LockdownMatrix.json" # The lockdown policy matrix
$logFilePath    = "C:\ProgramData\SSA\Logs\POSLockdownSystem.log" # Log file for this script

# ----- Function: Write-Log -----
# Logs a message to the applier's log file (auto-creates folder if missing)
function Write-Log {
    param([string]$Message)
    $logFolder = Split-Path $logFilePath
    if (-not (Test-Path $logFolder)) {
        New-Item -Path $logFolder -ItemType Directory -Force | Out-Null
    }
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "$timestamp - $Message" | Out-File -FilePath $logFilePath -Append -Encoding utf8
}

# ======= Main Logic =======
# For each user's decision file in LockdownQueue
Get-ChildItem -Path $queuePath -Filter "*.json" -ErrorAction SilentlyContinue | ForEach-Object {
    $sid = $_.BaseName
    try {
        # Read the lockdown decision (from detector script)
        $decision = Get-Content $_.FullName | ConvertFrom-Json

        # If user is EXEMPT (admin), skip lockdown
        if ($decision.Status -eq "EXEMPT") {
            Write-Log "[INFO] [$sid] Admin detected. No lockdown applied."
            return
        }

        # Load the lockdown policy matrix
        if (-not (Test-Path $matrixPath)) {
            Write-Log "[ERROR] Lockdown matrix not found at $matrixPath"
            return
        }
        $matrix = Get-Content $matrixPath | ConvertFrom-Json

        $unit = $decision.Unit
        $role = $decision.Role

        # Ensure the unit and role exist in the matrix
        if ($null -eq $unit -or $null -eq $role -or -not $matrix.PSObject.Properties.Name -contains $unit -or -not $matrix.$unit.PSObject.Properties.Name -contains $role) {
            Write-Log "[WARN] [$sid] No lockdown policy found for $unit / $role. Skipping."
            return
        }

        # Fetch the policy to apply for this unit/role
        $policy = $matrix.$unit.$role

        # Define the registry path for lockdown options for this user SID
        $regPath = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }

        # Apply each lockdown option in the policy
        foreach ($setting in $policy.PSObject.Properties) {
            $key = $setting.Name
            $value = $setting.Value
            try {
                if ($value) {
                    # Set the registry key (enable lockdown)
                    Set-ItemProperty -Path $regPath -Name $key -Value 1 -Type DWord -Force
                    Write-Log "[INFO] [$sid] Applied: $key=1"
                } else {
                    # Remove the registry key (disable lockdown)
                    Remove-ItemProperty -Path $regPath -Name $key -ErrorAction SilentlyContinue
                    Write-Log "[INFO] [$sid] Removed: $key"
                }
            } catch {
                Write-Log "[ERROR] [$sid] Failed to set $key: $($_.Exception.Message)"
            }
        }
        Write-Log "[INFO] [$sid] Lockdown applied for $unit/$role."

    } catch {
        Write-Log "[ERROR] [$sid] General failure: $($_.Exception.Message)"
    }
}
