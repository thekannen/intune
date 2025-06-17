# Downloads and updates scripts based on latest json file

$RepoURL = 'https://raw.githubusercontent.com/thekannen/intune/main/POS%20Lockdown/'
$ScriptList = 'scripts.json'

$localScriptPath = 'C:\ProgramData\SSA\Scripts'
$logFilePath = 'C:\ProgramData\SSA\Logs\DownloadLog.txt'
$localScriptJson = Join-Path $localScriptPath 'scripts.json'
$tempDownloadPath = Join-Path $env:TEMP "ssa_temp_download.ps1"

# --- Logging function ---
function Write-Log {
    param([string]$Message)

    $logFolder = Split-Path $logFilePath
    if (-not (Test-Path $logFolder)) {
        New-Item -Path $logFolder -ItemType Directory -Force | Out-Null
    }

    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "$timestamp - $Message" | Out-File -FilePath $logFilePath -Append -Encoding utf8
}

# Helper function to compute SHA256 hash
function Get-FileHashString {
    param ($Path)
    if (Test-Path $Path) {
        return (Get-FileHash -Algorithm SHA256 -Path $Path).Hash
    }
    return $null
}

# Ensure local folder exists
if (-not (Test-Path $localScriptPath)) {
    New-Item -Path $localScriptPath -ItemType Directory -Force
    Write-Log "Created Scripts directory at $localScriptPath"
}

# Download the latest scripts.json
try {
    Invoke-WebRequest -Uri "$RepoURL$ScriptList" -OutFile $localScriptJson -UseBasicParsing -ErrorAction Stop
    Write-Log "Downloaded latest scripts.json successfully."
} catch {
    Write-Log "ERROR downloading scripts.json: $($_.Exception.Message)"
    exit 1
}

# Parse scripts list
try {
    $scripts = (Get-Content -Path $localScriptJson | ConvertFrom-Json).scripts
    Write-Log "Parsed scripts.json successfully. Found $($scripts.Count) scripts to process."
} catch {
    Write-Log "ERROR parsing scripts.json: $($_.Exception.Message)"
    exit 1
}

foreach ($script in $scripts) {
    $remoteUrl = "$RepoURL$script"
    $localScriptFile = Join-Path $localScriptPath $script

    # Download the file to a temp location
    try {
        Invoke-WebRequest -Uri $remoteUrl -OutFile $tempDownloadPath -UseBasicParsing -ErrorAction Stop
        Write-Log "Downloaded $script successfully."
    } catch {
        Write-Log "ERROR downloading $script : $($_.Exception.Message)"
        continue
    }

    # Compare hashes
    $newHash = Get-FileHashString -Path $tempDownloadPath
    $existingHash = Get-FileHashString -Path $localScriptFile

    if ($newHash -ne $existingHash) {
        # Only overwrite if different
        Copy-Item -Path $tempDownloadPath -Destination $localScriptFile -Force
        Write-Log "Updated: $script (new hash detected)."
    } else {
        Write-Log "No change: $script (hash matched)."
    }
}

# Clean up temp file
if (Test-Path $tempDownloadPath) {
    Remove-Item $tempDownloadPath -Force
    Write-Log "Temporary download file removed."
}

Write-Log "Script download session complete."