# Parameters
$vaultName   = "IntuneVault"
$secretName  = "github-intune-repo-readonly"

# Define scripts to download (Key = URL, Value = local path)
$scriptsToDownload = @{
    "https://github.com/thekannen/intune/blob/75369287e3e4e783b04c9f82528ed967c2e7be6d/ToggleSettingsAccessByRole.ps1" = "C:\ProgramData\POSControl\ToggleSettingsAccessByRole.ps1"
    "https://github.com/thekannen/intune/blob/75369287e3e4e783b04c9f82528ed967c2e7be6d/ToggleSettingsScheduledTask.ps1"              = "C:\ProgramData\POSControl\ToggleSettingsScheduledTask.ps1"
    # Add more scripts as needed
}

# Ensure the Az modules are available
if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
    Install-Module -Name Az -Scope CurrentUser -Force
}
if (-not (Get-Module -ListAvailable -Name Az.KeyVault)) {
    Install-Module -Name Az.KeyVault -Scope CurrentUser -Force
}

# Authenticate using managed identity
Connect-AzAccount -Identity | Out-Null

# Retrieve GitHub token from Key Vault
$githubToken = Get-AzKeyVaultSecret -VaultName $vaultName -Name $secretName -AsPlainText

# Build the auth header
$headers = @{ Authorization = "token $githubToken" }

# Loop through each script and download it
foreach ($url in $scriptsToDownload.Keys) {
    $localPath = $scriptsToDownload[$url]
    $folder = Split-Path -Path $localPath -Parent

    if (-not (Test-Path $folder)) {
        New-Item -Path $folder -ItemType Directory -Force | Out-Null
    }

    try {
        Invoke-WebRequest -Uri $url -Headers $headers -OutFile $localPath -UseBasicParsing
        Write-Host "Downloaded: $url to $localPath"
    }
    catch {
        Write-Warning "Failed to download $url - $_"
    }
}
