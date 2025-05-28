# Run-UserScriptsFromGithubManifest.ps1
# Description:
#   - Reads a JSON manifest from a public GitHub URL
#   - For each script listed, attempts to locate and execute it from local storage
#   - Intended to be run in the context of the currently logged-in user (e.g., via scheduled task)
#   - Ensures that scripts run with proper user-level access (HKCU, profile-based changes)

# Local folder where scripts should be pre-downloaded by the SYSTEM task
$folder = "C:\ProgramData\IntuneControl"

# URL of the JSON manifest defining which scripts to run
$manifestUrl = "https://raw.githubusercontent.com/thekannen/intune/main/scripts.json"

try {
    # Attempt to download and parse the JSON manifest
    $manifest = Invoke-RestMethod -Uri $manifestUrl -UseBasicParsing

    # Loop through each script listed in the manifest
    foreach ($scriptName in $manifest.scripts) {
        # Construct full local file path
        $localPath = Join-Path $folder $scriptName

        # If the file exists locally, execute it in the current user context
        if (Test-Path $localPath) {
            Write-Host "Running $scriptName"
            powershell.exe -ExecutionPolicy Bypass -File "`"$localPath`""
        } else {
            # Warn if script is missing
            Write-Warning "Script not found: $localPath"
        }
    }
} catch {
    # Catch any errors with fetching/parsing the manifest or executing scripts
    Write-Error "Failed to process script manifest or run scripts: $_"
}
