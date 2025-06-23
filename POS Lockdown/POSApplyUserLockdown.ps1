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

# Paths
$matrixPath  = 'C:\ProgramData\SSA\Scripts\LockdownMatrix.json'
$queuePath   = 'C:\ProgramData\SSA\LockdownQueue'
$logFilePath = 'C:\ProgramData\SSA\Logs\POSLockdownSystem.log'

# Delay to let detector finish
Start-Sleep -Seconds 5

# Logging function
default param
function Write-Log {
    param([string]$Message)
    $folder = Split-Path $logFilePath
    if (-not (Test-Path $folder)) { New-Item -Path $folder -ItemType Directory -Force | Out-Null }
    "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) - $Message" |
        Out-File -FilePath $logFilePath -Append -Encoding utf8
}

# Registry mapping
$RegMap = @{
    'NoClose'             = @{ Path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer';      Type = 'DWord' }
    'NoControlPanel'      = @{ Path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer';      Type = 'DWord' }
    'NoRun'               = @{ Path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer';      Type = 'DWord' }
    'NoViewContextMenu'   = @{ Path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer';      Type = 'DWord' }
    'NoFileMenu'          = @{ Path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer';      Type = 'DWord' }
    'NoFolderOptions'     = @{ Path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer';      Type = 'DWord' }
    'NoSetFolders'        = @{ Path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer';      Type = 'DWord' }
    'NoSetTaskbar'        = @{ Path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer';      Type = 'DWord' }
    'NoSMHelp'            = @{ Path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer';      Type = 'DWord' }
    'DisableRegistryTools'= @{ Path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System';        Type = 'DWord' }
    'DisableCMD'          = @{ Path = 'Software\\Policies\\Microsoft\\Windows\\System';                       Type = 'DWord' }
    'EnableScripts'       = @{ Path = 'Software\\Policies\\Microsoft\\Windows\\System';                       Type = 'DWord' }
    'ExecutionPolicy'     = @{ Path = 'Software\\Policies\\Microsoft\\Windows\\System';                       Type = 'String' }
    'RemoveWindowsStore'  = @{ Path = 'Software\\Policies\\Microsoft\\WindowsStore';                         Type = 'DWord' }
    'NoEdge'              = @{ Path = $null;                                                          Type = 'DWord' }
}

# 1) Sanity-check queue folder and list files
Write-Log ("[INFO] Scanning queue directory: {0}" -f $queuePath)
$files = Get-ChildItem -Path $queuePath -Filter '*.txt' -ErrorAction SilentlyContinue
$fileNames = $files | Select-Object -ExpandProperty Name
Write-Log ("[INFO] Found {0} queue file(s): {1}" -f $files.Count, ($fileNames -join ', '))

# Main loop
foreach ($file in $files) {
    $sid     = $file.BaseName
    $company = $null; $role = $null

    Start-Sleep -Seconds 2

    # Read and parse queue
    try {
        $lines = Get-Content $file.FullName -ErrorAction Stop
        Write-Log ("[DEBUG] Raw queue lines for SID={0} -> {1}" -f $sid, ($lines -join ' | '))
        foreach ($line in $lines) {
            if ($line -match '^company:\s*(.+)$') { $company = $matches[1] }
            if ($line -match '^role:\s*(.+)$')    { $role    = $matches[1] }
        }
        Write-Log ("[INFO] Parsed queue for SID={0}: company={1}, role={2}" -f $sid, $company, $role)
    } catch {
        Write-Log ("[ERROR] Failed reading queue file {0}: {1}" -f $file.FullName, $_.Exception.Message)
        continue
    }

    # Load matrix and select policy
    $policy = $null
    if (Test-Path $matrixPath) {
        try {
            $matrix = Get-Content $matrixPath -Raw | ConvertFrom-Json
            if ($matrix.PSObject.Properties.Name -contains $company -and $matrix.$company.PSObject.Properties.Name -contains $role) {
                $policy = $matrix.$company.$role
                Write-Log ("[INFO] Using matrix policy for {0}/{1}" -f $company, $role)
            } else {
                Write-Log ("[WARN] No policy found for {0}/{1}; skipping" -f $company, $role)
            }
        } catch {
            Write-Log ("[ERROR] Failed parsing matrix: {0}" -f $_.Exception.Message)
        }
    } else {
        Write-Log ("[ERROR] Matrix file not found: {0}" -f $matrixPath)
    }
    if (-not $policy) { continue }

    # Apply each setting
    foreach ($kv in $policy.PSObject.Properties) {
        $name  = $kv.Name
        $value = $kv.Value

        if ($RegMap.ContainsKey($name) -and $RegMap[$name].Path) {
            $relPath = $RegMap[$name].Path
            $hkuPath = "HKU:\$sid\$relPath"
            $type    = $RegMap[$name].Type
            try {
                if ($value) {
                    # Ensure registry key exists
                    if (-not (Test-Path $hkuPath)) { New-Item -Path $hkuPath -Force | Out-Null }
                    $valToSet = if ($type -eq 'String') { 'Restricted' } else { 1 }
                    Set-ItemProperty -Path $hkuPath -Name $name -Value $valToSet -Type $type -Force
                    Write-Log ("[INFO] [{0}] Set {1}={2} ({3}) at {4}" -f $sid, $name, $valToSet, $type, $hkuPath)
                } else {
                    Remove-ItemProperty -Path $hkuPath -Name $name -ErrorAction SilentlyContinue
                    Write-Log ("[INFO] [{0}] Removed {1} from {2}" -f $sid, $name, $hkuPath)
                }
            } catch {
                Write-Log ("[ERROR] [{0}] Error setting/removing {1}: {2}" -f $sid, $name, $_.Exception.Message)
            }
        } elseif ($name -eq 'NoEdge' -and $value) {
            Write-Log ("[WARN] [{0}] Edge blocking not implemented. Use AppLocker/SRP." -f $sid)
        }
    }

    Write-Log ("[INFO] Completed processing for SID={0} ({1}/{2})" -f $sid, $company, $role)
}

#Dragon5
