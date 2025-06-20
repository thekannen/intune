# ------------------------------
# POSApplyUserLockdown.ps1
# ------------------------------
# SYSTEM-context script to apply or clear lockdown based on per-user SID cache and matrix.
# Works uniformly on Windows 10 & 11.
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
    # Explorer Policies
    'NoClose'             = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";      Type="DWord" }
    'NoControlPanel'      = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";      Type="DWord" }
    'NoRun'               = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";      Type="DWord" }
    'NoViewContextMenu'   = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";      Type="DWord" }
    'NoFileMenu'          = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";      Type="DWord" }
    'NoFolderOptions'     = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";      Type="DWord" }
    'NoSetFolders'        = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";      Type="DWord" }
    'NoSetTaskbar'        = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";      Type="DWord" }
    'NoSMHelp'            = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";      Type="DWord" }
    # System-level tools
    'DisableRegistryTools' = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\System";        Type="DWord" }
    # Command-line and scripting restrictions
    'DisableCMD'          = @{ Path = "Software\Policies\Microsoft\Windows\System";                       Type="DWord" }
    'EnableScripts'       = @{ Path = "Software\Policies\Microsoft\Windows\System";                       Type="DWord" }
    'ExecutionPolicy'     = @{ Path = "Software\Policies\Microsoft\Windows\System";                       Type="String" }
    # App Store lockdown
    'RemoveWindowsStore'  = @{ Path = "Software\Policies\Microsoft\WindowsStore";                         Type="DWord" }
    # Edge Block (not implemented - see below)
    'NoEdge'              = @{ Path = $null; Type="DWord" }
}

# MAIN LOGIC
Get-ChildItem -Path $queuePath -Filter '*.txt' -ErrorAction SilentlyContinue | ForEach-Object {
    $sid = $_.BaseName
    $decision = (Get-Content $_.FullName -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
    Write-Log "[INFO] Processing SID=$sid; Decision=$decision"

    if ($decision -eq 'EXEMPT') {
        Write-Log "[INFO] [$sid] Admin detected. No lockdown applied."
        return
    }

    # Read matrix for this user
    $unit = "Unknown"
    $role = "Unknown"
    $policy = @{}

    # (Optional: Read username/company/role from a cache or from registry/SID logic if needed)

    if (Test-Path $matrixPath) {
        try {
            $matrix = Get-Content $matrixPath | ConvertFrom-Json
            # If you store unit/role somewhere, fetch it here. Otherwise, use default
            # For this example, set defaults. Update to dynamically set as needed.
            $unit = "CFZ"
            $role = "POS"
            if ($matrix.PSObject.Properties.Name -contains $unit -and $matrix.$unit.PSObject.Properties.Name -contains $role) {
                $policy = $matrix.$unit.$role
                Write-Log "[INFO] [$sid] Using lockdown matrix policy for $unit/$role"
            } else {
                Write-Log "[WARN] [$sid] No lockdown policy found for $unit/$role, skipping."
                return
            }
        } catch {
            Write-Log "[ERROR] [$sid] Failed to parse lockdown matrix: $($_.Exception.Message)"
            return
        }
    } else {
        Write-Log "[ERROR] [$sid] Lockdown matrix not found at $matrixPath"
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
        }
        elseif ($name -eq "NoEdge") {
            # Not a real registry lockdown; log that this is not implemented
            if ($value) {
                Write-Log "[WARN] [$sid] Edge browser blocking is not implemented via registry. Use AppLocker or SRP for real blocking."
                # Optionally, insert AppLocker/deny Edge logic here
            }
        }
        else {
            Write-Log "[WARN] [$sid] Unknown setting '$name' found in matrix. No action taken."
        }
    }

    Write-Log "[INFO] Completed processing SID=$sid with matrix decision."
}
