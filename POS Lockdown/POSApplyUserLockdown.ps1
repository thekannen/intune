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

function Get-MostRestrictivePolicy {
    return @{
        NoClose             = $true
        NoControlPanel      = $true
        NoRun               = $true
        NoViewContextMenu   = $true
        NoFileMenu          = $true
        NoFolderOptions     = $true
        NoSetFolders        = $true
        NoSetTaskbar        = $true
        NoSMHelp            = $true
        DisableRegistryTools= $true
        DisableCMD          = $true
        EnableScripts       = $false
        ExecutionPolicy     = $true
        RemoveWindowsStore  = $true
        NoEdge              = $true
    }
}

# Registry mapping for each setting
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
    'DisableRegistryTools'= @{ Path = "Software\Microsoft\Windows\CurrentVersion\Policies\System";        Type="DWord" }
    'DisableCMD'          = @{ Path = "Software\Policies\Microsoft\Windows\System";                       Type="DWord" }
    'EnableScripts'       = @{ Path = "Software\Policies\Microsoft\Windows\System";                       Type="DWord" }
    'ExecutionPolicy'     = @{ Path = "Software\Policies\Microsoft\Windows\System";                       Type="String" }
    'RemoveWindowsStore'  = @{ Path = "Software\Policies\Microsoft\WindowsStore";                         Type="DWord" }
    'NoEdge'              = @{ Path = $null; Type="DWord" }
}

# MAIN LOGIC
Get-ChildItem -Path $queuePath -Filter '*.txt' -ErrorAction SilentlyContinue | ForEach-Object {
    $sid = $_.BaseName
    $company = $null
    $role = $null

    # Parse the queue file (company/role)
    try {
        $lines = Get-Content $_.FullName -ErrorAction Stop
        foreach ($line in $lines) {
            if ($line -match '^company:\s*(.+)$') { $company = $matches[1] }
            if ($line -match '^role:\s*(.+)$')    { $role = $matches[1] }
        }
        Write-Log "[INFO] SID=${sid} Company=${company} Role=${role}"
    } catch {
        Write-Log "[ERROR] Failed to read queue file $($_.FullName): $($_.Exception.Message)"
        return
    }

    # Load lockdown matrix
    $policy = $null
    if (Test-Path $matrixPath) {
        try {
            $matrix = Get-Content $matrixPath | ConvertFrom-Json
            if ($company -and $role -and
                $matrix.PSObject.Properties.Name -contains $company -and
                $matrix.$company.PSObject.Properties.Name -contains $role
            ) {
                $policy = $matrix.$company.$role
                Write-Log "[INFO] Using matrix lockdown policy for ${company}/${role}"
            } else {
                Write-Log "[WARN] No lockdown policy found for ${company}/${role}; applying most restrictive"
                $policy = Get-MostRestrictivePolicy
            }
        } catch {
            Write-Log "[ERROR] Failed to parse lockdown matrix: $($_.Exception.Message)"
            $policy = Get-MostRestrictivePolicy
        }
    } else {
        Write-Log "[ERROR] Lockdown matrix not found at $matrixPath; applying most restrictive"
        $policy = Get-MostRestrictivePolicy
    }

    # Apply each policy item
    foreach ($setting in $policy.GetEnumerator()) {
        $name = $setting.Key
        $value = $setting.Value

        if ($RegMap.ContainsKey($name) -and $RegMap[$name].Path) {
            $regRelPath = $RegMap[$name].Path
            $regPath = "Registry::HKEY_USERS\${sid}\${regRelPath}"
            $valueKind = $RegMap[$name].Type
            try {
                if ($value) {
                    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
                    $valueToSet = if ($valueKind -eq "String") { "Restricted" } else { 1 }
                    Set-ItemProperty -Path $regPath -Name $name -Value $valueToSet -Type $valueKind -Force
                    Write-Log "[INFO] [${sid}] Set ${name} = ${valueToSet} (${valueKind}) at ${regPath}"
                } else {
                    Remove-ItemProperty -Path $regPath -Name $name -ErrorAction SilentlyContinue
                    Write-Log "[INFO] [${sid}] Removed ${name} from ${regPath}"
                }
            } catch {
                Write-Log "[ERROR] [${sid}] Error setting/removing ${name}: $($_.Exception.Message)"
            }
        }
        elseif ($name -eq "NoEdge") {
            # Not a real registry lockdown; log that this is not implemented
            if ($value) {
                Write-Log "[WARN] [${sid}] Edge browser blocking is not implemented in registry. Use AppLocker/SRP for real blocking."
            }
        }
        else {
            Write-Log "[WARN] [${sid}] Unknown setting '${name}' found in policy. No action taken."
        }
    }

    Write-Log "[INFO] Completed processing SID=${sid} for company=${company} role=${role}"
}
