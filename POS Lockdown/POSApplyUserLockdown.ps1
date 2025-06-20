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

$RegMap = @{
    # Explorer Policies
    'NoClose'           = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Type="DWord" }
    'NoControlPanel'    = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Type="DWord" }
    'NoRun'             = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Type="DWord" }
    'NoViewContextMenu' = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Type="DWord" }
    'NoFileMenu'        = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Type="DWord" }
    'NoFolderOptions'   = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Type="DWord" }
    'NoSetFolders'      = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Type="DWord" }
    'NoSetTaskbar'      = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Type="DWord" }
    'NoSMHelp'          = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Type="DWord" }
    # System-level tools
    'DisableRegistryTools' = @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\System"; Type="DWord" }
    # Command-line and scripting restrictions
    'DisableCMD'        = @{ Path = "Software\Policies\Microsoft\Windows\System"; Type="DWord" }
    'EnableScripts'     = @{ Path = "Software\Policies\Microsoft\Windows\System"; Type="DWord" }
    'ExecutionPolicy'   = @{ Path = "Software\Policies\Microsoft\Windows\System"; Type="String" }
    # App Store lockdown
    'RemoveWindowsStore'= @{ Path = "Software\Policies\Microsoft\WindowsStore"; Type="DWord" }
    # Edge Block (not registry; informational)
    'NoEdge'            = @{ Path = $null; Type="DWord" }
}

function Get-MostRestrictivePolicy {
    # Everything set to true (most restricted)
    return @{
        NoClose = $true
        NoControlPanel = $true
        NoRun = $true
        NoViewContextMenu = $true
        NoFileMenu = $true
        NoFolderOptions = $true
        NoSetFolders = $true
        NoSetTaskbar = $true
        NoSMHelp = $true
        DisableRegistryTools = $true
        DisableCMD = $true
        EnableScripts = $false
        ExecutionPolicy = $true
        RemoveWindowsStore = $true
        NoEdge = $true
    }
}

Get-ChildItem -Path $queuePath -Filter '*.txt' -ErrorAction SilentlyContinue | ForEach-Object {
    $sid = $_.BaseName
    $decisionObj = $null
    try {
        $decisionJson = Get-Content $_.FullName -Raw | ConvertFrom-Json
        $decisionObj = $decisionJson
    } catch {
        Write-Log "[ERROR] [$sid] Failed to parse decision file; using legacy mode: $($_.Exception.Message)"
        # Fallback: treat as legacy "LOCKDOWN"/"EXEMPT"
        $decisionText = Get-Content $_.FullName -ErrorAction SilentlyContinue | Select-Object -First 1
        $decisionObj = @{ status = $decisionText; company = "Unknown"; role = "Unknown" }
    }

    $status = $decisionObj.status
    $unit   = $decisionObj.company
    $role   = $decisionObj.role

    Write-Log "[INFO] Processing SID=$sid; Status=$status; Unit=$unit; Role=$role"

    if ($status -eq 'EXEMPT') {
        Write-Log "[INFO] [$sid] Admin detected. No lockdown applied."
        return
    }

    # Get policy from matrix
    $policy = $null
    if (Test-Path $matrixPath) {
        try {
            $matrix = Get-Content $matrixPath | ConvertFrom-Json
            if ($matrix.PSObject.Properties.Name -contains $unit -and $matrix.$unit.PSObject.Properties.Name -contains $role) {
                $policy = $matrix.$unit.$role
                Write-Log "[INFO] [$sid] Using matrix policy for $unit/$role: $($policy | ConvertTo-Json -Compress)"
            } else {
                Write-Log "[WARN] [$sid] No matrix policy for $unit/$role; using most restrictive."
                $policy = Get-MostRestrictivePolicy
            }
        } catch {
            Write-Log "[ERROR] [$sid] Failed to parse matrix: $($_.Exception.Message)"
            $policy = Get-MostRestrictivePolicy
        }
    } else {
        Write-Log "[ERROR] [$sid] Matrix file not found at $matrixPath"
        $policy = Get-MostRestrictivePolicy
    }

    # Apply or remove settings per matrix
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
                Write-Log "[WARN] [$sid] Edge blocking is not done via registry. Use AppLocker/SRP."
            }
        }
        else {
            Write-Log "[WARN] [$sid] Unknown setting '$name' in matrix. No action taken."
        }
    }

    Write-Log "[INFO] Completed processing SID=$sid with matrix decision."
}
