# ------------------------------
# POSApplyUserLockdown.ps1
# ------------------------------

<#
  - Reads company/role from queue
  - Loads LockdownMatrix.json
  - Applies per-setting registry lockdown
  - Full logging and debug output
  - Includes brief delays for sequencing
#>

$matrixPath   = "C:\ProgramData\SSA\Scripts\LockdownMatrix.json"
$queuePath    = "C:\ProgramData\SSA\LockdownQueue"
$logFilePath  = "C:\ProgramData\SSA\Logs\POSLockdownSystem.log"

# Delay to wait for detector to finish
Start-Sleep -Seconds 5

# Logging function
default param
function Write-Log {
    param([string]$Message)
    $folder = Split-Path $logFilePath
    if (!(Test-Path $folder)) { New-Item -Path $folder -ItemType Directory -Force | Out-Null }
    "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) - $Message" |
        Out-File -FilePath $logFilePath -Append -Encoding utf8
}

# Registry mapping
$RegMap = @{
    'NoClose'             = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Type = 'DWord' }
    'NoControlPanel'      = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Type = 'DWord' }
    'NoRun'               = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Type = 'DWord' }
    'NoViewContextMenu'   = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Type = 'DWord' }
    'NoFileMenu'          = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Type = 'DWord' }
    'NoFolderOptions'     = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Type = 'DWord' }
    'NoSetFolders'        = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Type = 'DWord' }
    'NoSetTaskbar'        = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Type = 'DWord' }
    'NoSMHelp'            = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Type = 'DWord' }
    'DisableRegistryTools'= @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\System';   Type = 'DWord' }
    'DisableCMD'          = @{ Path = 'Software\Policies\Microsoft\Windows\System';                  Type = 'DWord' }
    'EnableScripts'       = @{ Path = 'Software\Policies\Microsoft\Windows\System';                  Type = 'DWord' }
    'ExecutionPolicy'     = @{ Path = 'Software\Policies\Microsoft\Windows\System';                  Type = 'String' }
    'RemoveWindowsStore'  = @{ Path = 'Software\Policies\Microsoft\WindowsStore';                    Type = 'DWord' }
    'NoEdge'              = @{ Path = $null;                                                     Type = 'DWord' }
}

# 1) Sanity-check queue folder and files
Write-Log "[INFO] Looking in $queuePath for .txt files"
$files = Get-ChildItem -Path $queuePath -Filter '*.txt' -ErrorAction SilentlyContinue
Write-Log "[INFO] Found $($files.Count) queue file(s): $($files | ForEach { $_.Name } -join ', ')"

# MAIN LOOP
Get-ChildItem -Path $queuePath -Filter '*.txt' -ErrorAction SilentlyContinue | ForEach-Object {
    $sid     = $_.BaseName
    $company = $null;  $role = $null

    # Delay slightly before reading
    Start-Sleep -Seconds 2

    # 2) Read raw lines and debug-log
    try {
        $lines = Get-Content $_.FullName -ErrorAction Stop
        Write-Log "[DEBUG] Raw queue lines for SID=$sid -> $($lines -join ' | ')"
        foreach ($line in $lines) {
            if ($line -match '^company:\s*(.+)$') { $company = $matches[1] }
            if ($line -match '^role:\s*(.+)$')    { $role    = $matches[1] }
        }
        Write-Log "[INFO] Parsed queue for SID=$sid: company=$company, role=$role"
    } catch {
        Write-Log "[ERROR] Failed to read queue file $($_.FullName): $($_.Exception.Message)"
        return
    }

    # 3) Load and select policy
    $policy = $null
    if (Test-Path $matrixPath) {
        try {
            $matrix = Get-Content $matrixPath | ConvertFrom-Json
            if ($company -and $role -and $matrix.PSObject.Properties.Name.Contains($company) -and `n                               $matrix.$company.PSObject.Properties.Name.Contains($role)) {
                $policy = $matrix.$company.$role
                Write-Log "[INFO] Using matrix lockdown policy for ${company}/${role}"   
            } else {
                Write-Log "[WARN] No policy found for ${company}/${role}; skipping or applying fallback"
            }
        } catch {
            Write-Log "[ERROR] Failed to parse lockdown matrix: $($_.Exception.Message)"
        }
    } else {
        Write-Log "[ERROR] Lockdown matrix not found at $matrixPath"
    }

    if (-not $policy) { Write-Log "[INFO] No policy loaded for SID=$sid; skipping."; return }

    # 4) Apply each registry setting
    foreach ($kv in $policy.PSObject.Properties) {
        $name  = $kv.Name
        $value = $kv.Value

        if ($RegMap.ContainsKey($name) -and $RegMap[$name].Path) {
            $relPath = $RegMap[$name].Path
            $regPath = "Registry::HKEY_USERS\$sid\$relPath"
            $type    = $RegMap[$name].Type
            try {
                if ($value) {
                    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
                    $valToSet = if ($type -eq 'String') { 'Restricted' } else { 1 }
                    Set-ItemProperty -Path $regPath -Name $name -Value $valToSet -Type $type -Force
                    Write-Log "[INFO] [$sid] Set $name=$valToSet ($type) @ $regPath"
                } else {
                    Remove-ItemProperty -Path $regPath -Name $name -ErrorAction SilentlyContinue
                    Write-Log "[INFO] [$sid] Removed $name from $regPath"
                }
            } catch {
                Write-Log "[ERROR] [$sid] Error setting/removing $name: $($_.Exception.Message)"
            }
        }
        elseif ($name -eq 'NoEdge') {
            if ($value) {
                Write-Log "[WARN] [$sid] Edge blocking not implemented here. Consider AppLocker/SRP."
            }
        }
        else {
            Write-Log "[WARN] [$sid] Unknown setting '$name' in policy."
        }
    }

    Write-Log "[INFO] Completed processing SID=$sid for company=$company role=$role"
}
