# Download-IntuneScriptsFromGithub.ps1
# Description:
#   - Downloads a list of scripts and resources from a public GitHub repository (RAW format)
#   - Stores the scripts in C:\ProgramData\IntuneControl
#   - Intended to run as SYSTEM (e.g., via a startup scheduled task) to preload user-facing scripts

# Define a list of scripts to download
# Keys = RAW GitHub URLs (pointing directly to files in your repo)
# Values = local destination paths on the device
$scriptsToDownload = @{
    # Manifest file that defines which scripts to run per user logon
    "https://raw.githubusercontent.com/thekannen/intune/main/scripts.json" = "C:\ProgramData\IntuneControl\scripts.json"

    # Toggles Settings app access based on user role
    "https://raw.githubusercontent.com/thekannen/intune/ToggleSettingsAccessByRole.ps1" = "C:\ProgramData\IntuneControl\ToggleSettingsAccessByRole.ps1"

    # Add additional scripts below as needed
    # "https://raw.githubusercontent.com/.../AnotherScript.ps1" = "C:\ProgramData\IntuneControl\AnotherScript.ps1"
}

# Loop through each defined script and download it
foreach ($url in $scriptsToDownload.Keys) {
    $localPath = $scriptsToDownload[$url]
    $folder = Split-Path -Path $localPath -Parent

    # Ensure the destination folder exists
    if (-not (Test-Path $folder)) {
        New-Item -Path $folder -ItemType Directory -Force | Out-Null
    }

    # Download the script and save it locally
    try {
        Invoke-WebRequest -Uri $url -OutFile $localPath -UseBasicParsing
        Write-Host "Downloaded: $url to $localPath"
    }
    catch {
        # Log a warning if any script fails to download
        Write-Warning "Failed to download $url - $_"
    }
}
