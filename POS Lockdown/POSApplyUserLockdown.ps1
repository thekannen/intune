# ------------------------------
# POSApplyUserLockdown.ps1
# Authors:
# --- Aaron Kannengieser - aaronkannengieser@thessagroup.com
# --- Dagan Uzzell - daganuzzell@thessagroup.com
# ------------------------------
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
Start-Sleep -Seconds 3

# Logging function
function Write-Log {
    param([string]$Message)
    $folder = Split-Path $logFilePath
    if (-not (Test-Path $folder)) {
        New-Item -Path $folder -ItemType Directory -Force | Out-Null
    }
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message" |
        Out-File -FilePath $logFilePath -Append -Encoding utf8
}

#–– TRACE INVOCATION ––
Write-Log "[TRACE] POSApplyUserLockdown.ps1 invoked at $(Get-Date -Format o)"

# Registry mapping (value names and registry paths)
$RegMap = @{
    'NoClose'                           = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer';          Type = 'DWord' }  # Disables "Shut Down" option from Start menu
    'NoControlPanel'                    = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer';          Type = 'DWord' }  # Hides or disables access to Control Panel
    'NoRun'                             = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer';          Type = 'DWord' }  # Disables the "Run" command from the Start menu
    'NoViewContextMenu'                 = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer';          Type = 'DWord' }  # Disables right-click context menus in File Explorer
    'NoFileMenu'                        = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer';          Type = 'DWord' }  # Removes File menu from Windows Explorer
    'NoFolderOptions'                   = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer';          Type = 'DWord' }  # Hides "Folder Options" from Tools menu
    'NoSetFolders'                      = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer';          Type = 'DWord' }  # Prevents changing folder view settings
    'NoSetTaskbar'                      = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer';          Type = 'DWord' }  # Prevents taskbar customization
    'NoSMHelp'                          = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer';          Type = 'DWord' }  # Removes Help option from Start menu
    'DisableRegistryTools'              = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\System';            Type = 'DWord' }  # Disables Registry Editor (regedit)
    'DisableCMD'                        = @{ Path = 'Software\Policies\Microsoft\Windows\System';                           Type = 'DWord' }  # Disables Command Prompt (cmd.exe)
    'EnableScripts'                     = @{ Path = 'Software\Policies\Microsoft\Windows\System';                           Type = 'DWord' }  # Enables or disables Windows Script Host (legacy)
    'ExecutionPolicy'                   = @{ Path = 'Software\Policies\Microsoft\Windows\System';                           Type = 'String' } # Sets PowerShell script execution policy (e.g., Restricted)
    'RemoveWindowsStore'                = @{ Path = 'Software\Policies\Microsoft\WindowsStore';                             Type = 'DWord' }  # Removes access to Microsoft Store
    'NoEdge'                            = @{ Path = $null;                                                                  Type = 'DWord' }  # Not enforced via registry — use AppLocker/SRP to block Edge
    'NoDesktop'                         = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer';          Type = 'DWord' }  # Hides desktop icons
    'NoTaskMgr'                         = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\System';            Type = 'DWord' }  # Disables Task Manager
    'DisableChangePassword'             = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\System';            Type = 'DWord' }  # Disables "Change Password" in Ctrl+Alt+Del screen
    'NoStartMenuMorePrograms'           = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer';          Type = 'DWord' }  # Hides "All Apps" list in Start menu
    'DisableNotificationCenter'         = @{ Path = 'Software\Policies\Microsoft\Windows\Explorer';                         Type = 'DWord' }  # Disables Action Center (notification center)
    'DisableSystemToastNotifications'   = @{ Path = 'Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'; Type = 'DWord' }  # Disables system-wide toast notifications
}


# 1) Sanity-check queue folder
Write-Log ("[INFO] Scanning queue directory: {0}" -f $queuePath)
$files = Get-ChildItem -Path $queuePath -Filter '*.txt' -ErrorAction SilentlyContinue
$fileNames = $files | Select-Object -ExpandProperty Name
Write-Log ("[INFO] Found {0} queue file(s): {1}" -f $files.Count, ($fileNames -join ', '))

$changesMade = $false

# 2) Process each queue file
foreach ($file in $files) {
    $sid     = $file.BaseName
    $company = $null; $role = $null

    # Detect if the SID is mounted
    if (-not (Test-Path "Registry::HKEY_USERS\$sid")) {
        Write-Log ("[WARN] SID {0} not loaded into HKU. Skipping." -f $sid)
        continue
    }

    # Read company/role
    try {
        $lines = Get-Content $file.FullName -ErrorAction Stop
        Write-Log ([string]::Format("[DEBUG] Queue $($file.Name): {0}", ($lines -join ' | ')))
        foreach ($line in $lines) {
            if ($line -match '^company:\s*(.+)$') { $company = $matches[1] }
            if ($line -match '^role:\s*(.+)$')    { $role    = $matches[1] }
        }
        Write-Log ("[INFO] Parsed queue for SID={0}: company={1}, role={2}" -f $sid, $company, $role)
    } catch {
        Write-Log ("[ERROR] Reading queue file '{0}': {1}" -f $file.FullName, $_.Exception.Message)
        continue
    }

    # Skip local, unknown, or admin accounts
    if ($company -in @('LOCAL', 'Unknown') -or $role -in @('LOCAL', 'Unknown')) {
        Write-Log ("[INFO] Skipping non-target user SID={0} (company={1}, role={2})" -f $sid, $company, $role)
        continue
    }

    # Resolve NTAccount to catch built-in admins
    try {
        $ntAccount = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
        if ($ntAccount -match '\\Administrator$' -or $ntAccount -match 'Domain Admins') {
            Write-Log ("[INFO] Skipping admin account: {0}" -f $ntAccount)
            continue
        }
    } catch {
        Write-Log ("[WARN] Could not resolve SID {0} to NTAccount: {1}" -f $sid, $_.Exception.Message)
    }

    # Load matrix policy
    $policy = $null
    if (Test-Path $matrixPath) {
        try {
            $matrix = Get-Content $matrixPath -Raw | ConvertFrom-Json
            if ($matrix.PSObject.Properties.Name -contains $company -and $matrix.$company.PSObject.Properties.Name -contains $role) {
                $policy = $matrix.$company.$role
                Write-Log ("[INFO] Using matrix policy for {0}/{1}" -f $company, $role)
            } else {
                Write-Log ("[WARN] No matrix policy for {0}/{1}, skipping" -f $company, $role)
            }
        } catch {
            Write-Log ("[ERROR] Parsing matrix JSON: {0}" -f $_.Exception.Message)
        }
    } else {
        Write-Log ("[ERROR] Matrix file not found: {0}" -f $matrixPath)
    }

    if (-not $policy) { continue }

    # Apply each registry setting
    foreach ($prop in $policy.PSObject.Properties) {
        $name  = $prop.Name
        $value = $prop.Value

        if ($RegMap.ContainsKey($name) -and $RegMap[$name].Path) {
            $relPath = $RegMap[$name].Path
            $hkuPath = "Registry::HKEY_USERS\$sid\$relPath"
            $type    = $RegMap[$name].Type

            try {
                # Ensure key exists
                if (-not (Test-Path $hkuPath)) {
                    New-Item -Path $hkuPath -Force | Out-Null
                }

                if ($value) {
                    $dw = if ($type -eq 'String') { [string]$value } else { 1 }

                    $current = Get-ItemProperty -Path $hkuPath -Name $name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $name -ErrorAction SilentlyContinue

                    if ($current -ne $dw) {
                        New-ItemProperty -Path $hkuPath -Name $name -Value $dw -PropertyType $type -Force | Out-Null
                        Write-Log ("[INFO] [{0}] Set {1} ({2}) at {3}" -f $sid, $name, $type, $hkuPath)
                        $changesMade = $true
                    } else {
                        Write-Log ("[DEBUG] [{0}] {1} already set correctly, skipping." -f $sid, $name)
                    }
                } else {
                    if (Test-Path "$hkuPath\$name") {
                        Remove-ItemProperty -Path $hkuPath -Name $name -ErrorAction SilentlyContinue
                        Write-Log ("[INFO] [{0}] Removed {1}" -f $sid, $name)
                        $changesMade = $true
                    } else {
                        Write-Log ("[DEBUG] [{0}] {1} already not set, skipping removal." -f $sid, $name)
                    }
                }
            } catch {
                Write-Log ("[ERROR] [{0}] {1} at {2}: {3}" -f $sid, $name, $hkuPath, $_.Exception.Message)
            }
        } elseif ($name -eq 'NoEdge' -and $value) {
            Write-Log ("[WARN] [{0}] Edge blocking not in registry. Use AppLocker/SRP." -f $sid)
        } else {
            Write-Log ("[DEBUG] [{0}] Policy '{1}' not found in RegMap. Skipping." -f $sid, $name)
        }
    }

    Write-Log ("[INFO] Completed processing SID={0} ({1}/{2})" -f $sid, $company, $role)
}

if ($changesMade) {
    Write-Log "[INFO] Policy changes detected. Restarting explorer.exe..."

    # Kill any running explorer.exe instances
    Get-Process explorer -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            Stop-Process -Id $_.Id -Force
            Write-Log ("[INFO] Stopped explorer.exe (PID: {0})" -f $_.Id)
        } catch {
            Write-Log ("[WARN] Could not stop explorer.exe: {0}" -f $_.Exception.Message)
        }
    }

    # Start explorer again
    try {
        Start-Process "explorer.exe"
        Write-Log "[INFO] Relaunched explorer.exe"
    } catch {
        Write-Log ("[ERROR] Failed to restart explorer.exe: {0}" -f $_.Exception.Message)
    }
} else {
    Write-Log "[INFO] No policy changes detected. Explorer restart skipped."
}


#Dagan2