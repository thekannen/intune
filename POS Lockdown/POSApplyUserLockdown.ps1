# ------------------------------
# POSApplyUserLockdown.ps1
# ------------------------------

$matrixPath  = "C:\ProgramData\SSA\Scripts\LockdownMatrix.json"
$queuePath   = "C:\ProgramData\SSA\LockdownQueue"
$logFilePath = "C:\ProgramData\SSA\Logs\POSLockdownSystem.log"

function Write-Log {
    param([string]$Message)
    $folder = Split-Path $logFilePath
    if (!(Test-Path $folder)) { New-Item -Path $folder -ItemType Directory -Force | Out-Null }
    "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) - $Message" | Out-File -FilePath $logFilePath -Append -Encoding utf8
}

# Mapping of setting names to registry paths and value types
$RegMap = @{
    'NoClose'             = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";      Type="DWord" }
    'NoControlPanel'      = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";      Type="DWord" }
    'NoRun'               = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";      Type="DWord" }
    'NoViewContextMenu'   = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";      Type="DWord" }
    'NoFileMenu'          = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";      Type="DWord" }
    'NoFolderOptions'     = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";      Type="DWord" }
    'NoSetFolders'        = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";      Type="DWord" }
    'NoSetTaskbar'        = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";      Type="DWord" }
    'NoSMHelp'            = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";      Type="DWord" }
    'DisableRegistryTools' = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\System";        Type="DWord" }
    'DisableCMD'          = @{ Path = "Software\Policies\Microsoft\Windows\System";                       Type="DWord" }
    'EnableScripts'       = @{ Path = "Software\Policies\Microsoft\Windows\System";                       Type="DWord" }
    'ExecutionPolicy'     = @{ Path = "Software\Policies\Microsoft\Windows\System";                       Type="String" }
    'RemoveWindowsStore'  = @{ Path = "Software\Policies\Microsoft\WindowsStore";                         Type="DWord" }
    'NoEdge'              = @{ Path = $null; Type="DWord" } # Not implemented; just logs warning
}

# MAIN LOGIC
Get-ChildItem -Path $queuePath -Filter '*.txt' -ErrorAction SilentlyContinue | ForEach-Object {
    $sid = $_.BaseName
    try {
        $decisionRaw = Get-Content $_.FullName -ErrorAction SilentlyContinue | Out-String | ConvertFrom-Json
    } catch {
        Write-Log "[ERROR] [$sid] Could not parse decision file as JSON: $($_.Exception.Message)"
        return
    }
    $status = $decisionRaw.Status
    Write-Log "[INFO] Processing SID=$sid; Status=$status"

    if ($status -eq 'EXEMPT') {
        Write-Log "[INFO] [$sid] Admin detected. No lockdown applied."
        return
    }

    $unit = $decisionRaw.Unit
    $role = $decisionRaw.Role
    if (-not $unit -or -not $role) {
        Write-Log "[WARN] [$sid] Missing unit or role in decision file, using Unknown/Unknown."
        $unit = "Unknown"; $role = "Unknown"
    }

    if (Test-Path $matrixPath) {
        try {
            $matrix = Get-Content $matrixPath | ConvertFrom-Json
            if ($matrix.PSObject.Properties.Name -contains $unit -and $matrix.$unit.PSObject.Properties.Name -contains $role) {
                $policy = $matrix.$unit.$role
                Write-Log "[INFO] [$sid] Matrix lockdown for $unit/$role"
            } else {
                Write-Log "[WARN] [$sid] No lockdown policy for $unit/$role. Skipping user."
                return
            }
        } catch {
            Write-Log "[ERROR] [$sid] Failed to parse lockdown matrix: $($_.Exception.Message)"
            return
        }
    } else {
        Write-Log "[ERROR] [$sid] Matrix not found at $matrixPath"
        return
    }

    foreach ($setting in $policy.GetEnumerator()) {
        $name = $setting.Key
        $value = $setting.Value

        if ($RegMap.ContainsKey($name) -and $RegMap[$name].Path) {
            $regRelPath = $RegMap[$name].Path
            $regPath = "Registry::HKEY_USERS\$sid\$regRelPath"
            $valueKind = $RegMap[$name].Type
            try {
                if ($value) {
                    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
                    $valueToSet = if ($valueKind -eq "String") { "Restricted" } else { 1 }
                    Set-ItemProperty -Path $regPath -Name $name -Value $valueToSet -Type $valueKind -Force
                    Write-Log "[INFO] [$sid] Set $name = $valueToSet ($valueKind) at $regPath"
                } else {
                    Remove-ItemProperty -Path $regPath -Name $name -ErrorAction SilentlyContinue
                    Write-Log "[INFO] [$sid] Removed setting: $name from $regPath"
                }
            } catch {
                Write-Log "[ERROR] [$sid] Error setting/removing $name : $($_.Exception.Message)"
            }
        } elseif ($name -eq "NoEdge") {
            if ($value) {
                Write-Log "[WARN] [$sid] NoEdge is not implemented (see docs for AppLocker/SRP)"
            }
        } else {
            Write-Log "[WARN] [$sid] Unknown setting '$name'."
        }
    }

    Write-Log "[INFO] Completed processing SID=$sid with matrix policy."
}
