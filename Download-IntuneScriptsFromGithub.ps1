# Define scripts to download (Key = RAW URL, Value = local path)
$scriptsToDownload = @{
    "https://raw.githubusercontent.com/thekannen/intune/75369287e3e4e783b04c9f82528ed967c2e7be6d/ToggleSettingsAccessByRole.ps1" = "C:\ProgramData\POSControl\ToggleSettingsAccessByRole.ps1"
    "https://raw.githubusercontent.com/thekannen/intune/75369287e3e4e783b04c9f82528ed967c2e7be6d/ToggleSettingsScheduledTask.ps1" = "C:\ProgramData\POSControl\ToggleSettingsScheduledTask.ps1"
    # Add more scripts as needed
}

# Download each script
foreach ($url in $scriptsToDownload.Keys) {
    $localPath = $scriptsToDownload[$url]
    $folder = Split-Path -Path $localPath -Parent

    if (-not (Test-Path $folder)) {
        New-Item -Path $folder -ItemType Directory -Force | Out-Null
    }

    try {
        Invoke-WebRequest -Uri $url -OutFile $localPath -UseBasicParsing
        Write-Host "Downloaded: $url to $localPath"
    }
    catch {
        Write-Warning "Failed to download $url - $_"
    }
}
