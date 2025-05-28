# Download-IntuneScriptsFromGithub.ps1

<#
.SYNOPSIS
    Preloads user-facing PowerShell scripts from GitHub to a local folder.

.DESCRIPTION
    - Downloads a manifest and script files from a public GitHub repository (raw format)
    - Saves all files under C:\ProgramData\IntuneControl
    - Executes any scripts defined in the JSON manifest immediately
    - Intended to run as SYSTEM (via NinjaOne policy, automation, or startup task)
    - Execution is non-interactive and assumes network connectivity

.NOTES
    Deployment platform: NinjaOne
    Execution context: SYSTEM
    Output location: C:\ProgramData\IntuneControl
#>

# Define a map of RAW GitHub URLs to local storage paths
$scriptsToDownload = @{
    # JSON manifest listing scripts to run in user context
    "https://raw.githubusercontent.com/thekannen/intune/main/scripts.json" = "C:\ProgramData\IntuneControl\scripts.json"

    # Script to toggle Settings access based on user role (HKCU)
    "https://raw.githubusercontent.com/thekannen/intune/main/ToggleSettingsAccessByRole.ps1" = "C:\ProgramData\IntuneControl\ToggleSettingsAccessByRole.ps1"

    # Example: Add more scripts below as needed
    # "https://raw.githubusercontent.com/..." = "C:\ProgramData\IntuneControl\YourScript.ps1"
}

# Download each defined script to the local folder
foreach ($url in $scriptsToDownload.Keys) {
    $localPath = $scriptsToDownload[$url]
    $folder = Split-Path -Path $localPath -Parent

    # Ensure the target directory exists
    if (-not (Test-Path $folder)) {
        New-Item -Path $folder -ItemType Directory -Force | Out-Null
    }

    # Attempt to download the file
    try {
        Invoke-WebRequest -Uri $url -OutFile $localPath -UseBasicParsing
        Write-Host "Downloaded: $url to $localPath"
    }
    catch {
        Write-Warning "Failed to download $url - $_"
    }
}

# Load and execute user-context scripts listed in the manifest
$manifestUrl = "https://raw.githubusercontent.com/thekannen/intune/main/scripts.json"

try {
    # Retrieve the manifest JSON file from GitHub
    $manifest = Invoke-RestMethod -Uri $manifestUrl -UseBasicParsing

    # Loop over each script name in the manifest
    foreach ($scriptName in $manifest.scripts) {
        $localPath = Join-Path "C:\ProgramData\IntuneControl" $scriptName

        # If the script file exists locally, invoke it
        if (Test-Path $localPath) {
            Write-Host "Running $scriptName"
            powershell.exe -ExecutionPolicy Bypass -File "`"$localPath`""
        } else {
            Write-Warning "Script not found: $localPath"
        }
    }
} catch {
    Write-Error "Failed to process script manifest or run scripts: $_"
}
