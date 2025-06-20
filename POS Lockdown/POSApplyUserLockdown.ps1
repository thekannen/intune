# ------------------------------
# POSApplyUserLockdown.ps1
# ------------------------------
# Applies lockdown policies from matrix file per user

$queuePath   = "C:\ProgramData\SSA\LockdownQueue"
$matrixPath  = "C:\ProgramData\SSA\Scripts\LockdownMatrix.json"
$logFilePath = "C:\ProgramData\SSA\Logs\POSLockdownSystem.log"

function Write-Log {
    param([string]$Message)
    $logFolder = Split-Path $logFilePath
    if (-not (Test-Path $logFolder)) { New-Item -Path $logFolder -ItemType Directory -Force | Out-Null }
    "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) - $Message" | Out-File -FilePath $logFilePath -Append -Encoding utf8
}

# For each user's decision file in LockdownQueue
Get-ChildItem -Path $queuePath -Filter "*.json" -ErrorAction SilentlyContinue | ForEach-Object {
    $sid = $_.BaseName
    try {
        $decision = Get-Content $_.FullName | ConvertFrom-Json

        if ($decision.Status -eq "EXEMPT") {
            Write-Log "[INFO] [$sid] Admin detected. No lockdown applied."
            return
        }

        if (-not (Test-Path $matrixPath)) {
            Write-Log "[ERROR] Lockdown matrix not found at $matrixPath"
            return
        }
        $matrix = Get-Content $matrixPath | ConvertFrom-Json

        $unit = $decision.Unit
        $role = $decision.Role

        if ($null -eq $unit -or $null -eq $role -or -not $matrix.PSObject.Properties.Name -contains $unit -or -not $matrix.$unit.PSObject.Properties.Name -contains $role) {
            Write-Log "[WARN] [$sid] No lockdown policy found for $unit / $role. Skipping."
            return
        }

        $policy = $matrix.$unit.$role

        $regPath = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }

        foreach ($setting in $policy.PSObject.Properties) {
            $key = $setting.Name
            $value = $setting.Value
            try {
                if ($value) {
                    Set-ItemProperty -Path $regPath -Name $key -Value 1 -Type DWord -Force
                    Write-Log "[INFO] [$sid] Applied: $key=1"
                } else {
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
