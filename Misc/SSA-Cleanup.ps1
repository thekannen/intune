# SSA-Cleanup.ps1
# Removes all SSA Lockdown scripts, registry entries, scheduled tasks, and related artifacts

$logPath = "C:\SSA-Cleanup.log"
function Log { param($m) ; "$((Get-Date).ToString("yyyy-MM-dd HH:mm:ss")) - $m" | Tee-Object -FilePath $logPath -Append }

Log "Starting SSA Lockdown cleanup..."

# 1. Remove Scheduled Tasks
$tasks = @(
    "SSA - Detect POS Lockdown (User)",
    "SSA - Apply POS Lockdown (System)",
    "SSA_ScriptUpdater"
)

foreach ($task in $tasks) {
    try {
        if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $task -Confirm:$false
            Log "Removed scheduled task: $task"
        }
    } catch {
        Log "Failed to remove task $task : $_"
    }
}

# 2. Delete ProgramData folders
$ssaPaths = @(
    "C:\ProgramData\SSA\Scripts",
    "C:\ProgramData\SSA\Secrets",
    "C:\ProgramData\SSA\Logs",
    "C:\ProgramData\SSA\LockdownQueue"
)

foreach ($path in $ssaPaths) {
    try {
        if (Test-Path $path) {
            Remove-Item -Path $path -Recurse -Force
            Log "Deleted folder: $path"
        }
    } catch {
        Log "Failed to delete $path : $_"
    }
}

# ------------------------------
# 3. Registry cleanup (SSA Lockdown)
# ------------------------------

$mountedHives = @{}
$mountedWithRegLoad = @{}

Get-ChildItem 'C:\Users' -Directory | Where-Object {
    ($_.Name -notin @('Default', 'Default User', 'Public', 'All Users')) -and
    (Test-Path "$($_.FullName)\NTUSER.DAT")
} | ForEach-Object {
    $userProfile = $_.FullName
    $userName = $_.Name
    $user = Get-LocalUser -Name $userName -ErrorAction SilentlyContinue
    $sid = if ($user) { $user.SID.Value } else { "SSA_TEMP_$userName" }

    if (-not (Test-Path "Registry::HKEY_USERS\$sid")) {
        try {
            reg load "HKU\$sid" "$userProfile\NTUSER.DAT" | Out-Null
            $mountedHives[$sid] = $true
            $mountedWithRegLoad[$sid] = $true
            Log "Mounted $userName hive as $sid"
        } catch {
            Log "Failed to mount $userName hive: $_"
        }
    } else {
        $mountedHives[$sid] = $true
        Log "Hive already loaded: $sid"
    }
}

Start-Sleep -Seconds 1

$RegMap = @{
    'NoClose'                           = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer';          Type = 'DWord' }
    'NoControlPanel'                    = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer';          Type = 'DWord' }
    'NoRun'                             = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer';          Type = 'DWord' }
    'NoViewContextMenu'                 = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer';          Type = 'DWord' }
    'NoFileMenu'                        = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer';          Type = 'DWord' }
    'NoFolderOptions'                   = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer';          Type = 'DWord' }
    'NoSetFolders'                      = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer';          Type = 'DWord' }
    'NoSetTaskbar'                      = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer';          Type = 'DWord' }
    'NoSMHelp'                          = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer';          Type = 'DWord' }
    'DisableRegistryTools'             = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\System';            Type = 'DWord' }
    'DisableCMD'                        = @{ Path = 'Software\Policies\Microsoft\Windows\System';                           Type = 'DWord' }
    'EnableScripts'                     = @{ Path = 'Software\Policies\Microsoft\Windows\System';                           Type = 'DWord' }
    'ExecutionPolicy'                   = @{ Path = 'Software\Policies\Microsoft\Windows\System';                           Type = 'String' }
    'RemoveWindowsStore'                = @{ Path = 'Software\Policies\Microsoft\WindowsStore';                             Type = 'DWord' }
    'NoDesktop'                         = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer';          Type = 'DWord' }
    'DisableTaskMgr'                    = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\System';            Type = 'DWord' }
    'DisableChangePassword'            = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\System';            Type = 'DWord' }
    'NoStartMenuMorePrograms'          = @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer';          Type = 'DWord' }
    'DisableNotificationCenter'        = @{ Path = 'Software\Policies\Microsoft\Windows\Explorer';                         Type = 'DWord' }
    'DisableSystemToastNotifications'  = @{ Path = 'Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'; Type = 'DWord' }
    'RemoveStartMenuPins'              = @{ Path = 'Software\Policies\Microsoft\Windows\StartLayout';                      Type = 'DWord' }
}

$changesMade = $false

foreach ($sid in $mountedHives.Keys) {
    foreach ($entry in $RegMap.GetEnumerator()) {
        $name = $entry.Key
        $pathRel = $entry.Value.Path
        if (-not $pathRel) { continue }

        $fullPath = "Registry::HKEY_USERS\$sid\$pathRel"

        try {
            if (Test-Path $fullPath) {
                $props = Get-ItemProperty -Path $fullPath -ErrorAction SilentlyContinue
                if ($props.PSObject.Properties.Name -contains $name) {
                    Remove-ItemProperty -Path $fullPath -Name $name -ErrorAction Stop
                    Log "Removed [$sid] registry value: $name from $fullPath"
                    $changesMade = $true
                } else {
                    Log "[$sid] registry value not present: $name at $fullPath"
                }
            } else {
                Log "[$sid] registry key not present: $fullPath"
            }
        } catch {
            Log "Failed to remove [$sid] $name from $fullPath : $_"
        }
    }
}

# Unload only hives we mounted ourselves
foreach ($sid in $mountedWithRegLoad.Keys) {
    try {
        reg unload "HKU\$sid" | Out-Null
        Log "Unloaded hive $sid"
    } catch {
        Log "Failed to unload hive $sid : $_"
    }
}

# 4. Optional explorer restart
if ($changesMade) {
    try {
        Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Process "explorer.exe"
        Log "Restarted explorer.exe to refresh settings"
    } catch {
        Log "Failed to restart explorer.exe: $_"
    }
} else {
    Log "No registry changes detected; skipping explorer restart"
}

Log "SSA Lockdown cleanup complete."
