# ------------------------------
# POSApplyUserLockdown.ps1 - Minimal JSON Test Version
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

# Map matrix keys to registry settings (update as needed)
$RegMap = @{
    'NoClose' = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";      Type="DWord" }
    'NoControlPanel' = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";      Type="DWord" }
    'NoRun' = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";      Type="DWord" }
    'NoViewContextMenu' = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";      Type="DWord" }
    'NoFileMenu' = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";      Type="DWord" }
    'NoFolderOptions' = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";      Type="DWord" }
    'NoSetFolders' = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";      Type="DWord" }
    'NoSetTaskbar' = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";      Type="DWord" }
    'NoSMHelp' = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";      Type="DWord" }
    'DisableRegistryTools' = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\System";        Type="DWord" }
    'DisableCMD' = @{ Path = "Software\Policies\Microsoft\Windows\System";                       Type="DWord" }
    'EnableScripts' = @{ Path = "Software\Policies\Microsoft\Windows\System";                       Type="DWord" }
    'ExecutionPolicy' = @{ Path = "Software\Policies\Microsoft\Windows\System";                       Type="String" }
    'RemoveWindowsStore' = @{ Path = "Software\Policies\Microsoft\WindowsStore";                         Type="DWord" }
    'NoEdge' = @{ Path = $null; Type="DWord" }
}

Get-ChildItem -Path $queuePath -Filter '*.json' -ErrorAction SilentlyContinue | ForEach-Object {
    $sid = $_.BaseName
    try {
        $decisionObj = Get-Content $_.FullName | ConvertFrom-Json
        $status = $decisionObj.Status
        Write-Log "[INFO] Processing SID=$sid; Status=$status"

        if ($status -eq 'EXEMPT') {
            Write-Log "[INFO] [$sid] Admin detected. No lockdown applied."
            return
        }

        $unit = $decisionObj.Unit
        $role = $decisionObj.Role

        if (-not (Test-Path $matrixPath)) {
            Write-Log "[ERROR] Lockdown matrix not found at $matrixPath"
            return
        }
        $matrix = Get-Content $matrixPath | ConvertFrom-Json

        if ($null -eq $unit -or $null -eq $role -or -not $matrix.PSObject.Properties.Name -contains $unit -or -not $matrix.$unit.PSObject.Properties.Name -contains $role) {
            Write-Log "[WARN] [$sid] No lockdown policy found for $unit / $role. Skipping."
            return
        }
        $policy = $matrix.$unit.$role

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
            }
            elseif ($name -eq "NoEdge") {
                if ($value) {
                    Write-Log "[WARN] [$sid] Edge browser blocking not implemented via registry."
                }
            }
            else {
                Write-Log "[WARN] [$sid] Unknown setting '$name' found in matrix. No action taken."
            }
        }
        Write-Log "[INFO] Completed processing SID=$sid with matrix decision."
    } catch {
        Write-Log "[ERROR] [$sid] General failure: $($_.Exception.Message)"
    }
}
