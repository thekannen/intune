# ------------------------------
# POSApplyUserLockdown.ps1
# ------------------------------
# SYSTEM-context script to apply or clear lockdown based on per-user SID cache.
# Treats each setting as a toggle: true => apply policy, false => remove if present.
# Works uniformly on Windows 10 & 11.
# ------------------------------

# --- CONFIGURABLE LOCKDOWN SETTINGS (true=apply, false=remove) ---
$LockdownOptions = @{
    # --- File Explorer and Start Menu restrictions ---
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' = @{
        'NoClose' = $true              # true disables Shut down, Restart, Sleep from Start menu; false enables them
        'NoControlPanel' = $true        # true blocks access to Control Panel and Settings app
        'NoRun' = $true                 # true hides Run dialog (Win + R)
        'NoViewContextMenu' = $true     # true disables right-click context menus in Explorer
        'NoFileMenu' = $true            # true hides the File menu in Explorer windows
        'NoFolderOptions' = $true       # true disables access to Folder Options (e.g. view hidden files)
        'NoSetFolders' = $true          # true prevents user from changing system folders like Documents
        'NoSetTaskbar' = $true          # true blocks taskbar customization (e.g. pinning, resizing)
        'NoSMHelp' = $true              # true hides the Help option in the Start menu
    }

    # --- System-level tools lockdown ---
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System' = @{
        'DisableRegistryTools' = $true  # true disables regedit.exe (Registry Editor)
    }

    # --- Command-line and scripting restrictions ---
    'HKCU:\Software\Policies\Microsoft\Windows\System' = @{
        'DisableCMD' = $true            # true disables Command Prompt entirely
        'EnableScripts' = $false        # false disables Windows Script Host (blocks .vbs/.js/.ps1 execution)
        'ExecutionPolicy' = $true       # true sets PowerShell to restricted mode (local enforcement required)
    }

    # --- App Store lockdown ---
    'HKCU:\Software\Policies\Microsoft\WindowsStore' = @{
        'RemoveWindowsStore' = $true    # true disables Microsoft Store app for this user
    }
}

$queuePath = "C:\ProgramData\SSA\LockdownQueue"
$logFilePath = "C:\ProgramData\SSA\Logs\POSLockdownSystem.log"

function Write-Log {
    param([string]$Message)
    $folder = Split-Path $logFilePath
    if (!(Test-Path $folder)) { New-Item -Path $folder -ItemType Directory -Force | Out-Null }
    "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) - $Message" |
        Out-File -FilePath $logFilePath -Append -Encoding utf8
}

Get-ChildItem -Path $queuePath -Filter '*.txt' -ErrorAction SilentlyContinue |
ForEach-Object {
    $sid = $_.BaseName
    $decision = (Get-Content $_.FullName -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
    Write-Log "[INFO] Processing SID=$sid; Decision=$decision"

    foreach ($hivePath in $LockdownOptions.Keys) {
        # Convert HKCU: to HKEY_USERS\SID (raw string for .NET)
        $keyName = "HKEY_USERS\$sid" + $hivePath.Substring(5)  # Removes 'HKCU:' prefix

        foreach ($settingKvp in $LockdownOptions[$hivePath].GetEnumerator()) {
            $name = $settingKvp.Key
            $value = $settingKvp.Value
            $apply = ($decision -eq 'LOCKDOWN')

            try {
                if ($apply) {
                    if (-not (Test-Path ("Registry::" + $keyName))) {
                        New-Item -Path ("Registry::" + $keyName) -Force | Out-Null
                        Write-Log "[INFO] Created registry key: Registry::$keyName"
                    }

                    $valueKind = if ($name -eq 'ExecutionPolicy') { 'String' } else { 'DWord' }
                    $valueToSet = if ($value) { 1 } else { 0 }

                    Set-ItemProperty -Path ("Registry::" + $keyName) -Name $name -Value $valueToSet -Type $valueKind -Force
                    Write-Log "[INFO] [$sid] Set $name = $valueToSet ($valueKind) at Registry::$keyName"
                }
                else {
                    Remove-ItemProperty -Path ("Registry::" + $keyName) -Name $name -ErrorAction SilentlyContinue
                    Write-Log "[INFO] [$sid] Removed setting: $name (if it existed)"
                }
            }
            catch {
                Write-Log "[ERROR] [$sid] Error setting/removing $name : $($_.Exception.Message)"
            }
        }
    }

    Write-Log "[INFO] Completed processing SID=$sid with decision=$decision"
}
