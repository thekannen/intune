# Create required directories
$basePath = "C:\ProgramData\SSA"
$folders = @("Scripts", "Secrets", "Logs")
foreach ($folder in $folders) {
    $fullPath = Join-Path $basePath $folder
    if (-Not (Test-Path $fullPath)) {
        New-Item -Path $fullPath -ItemType Directory -Force
    }
}

# Set Permissions (Restrictive but readable by users for Scripts and Secrets)
icacls "$basePath\Secrets" /inheritance:r
icacls "$basePath\Secrets" /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Authenticated Users:(OI)(CI)RX"

icacls "$basePath\Scripts" /inheritance:r
icacls "$basePath\Scripts" /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Authenticated Users:(OI)(CI)RX"

# Create a secret file (replace 'your-client-secret-here' securely)
$clientSecret = 'YOUR-GRAPH-API-CLIENT-SECRET'
Set-Content -Path "$basePath\Secrets\GraphApiCred.txt" -Value $clientSecret -Force

# Download-IntuneScriptsFromGithub.ps1
$downloadScript = @"
# Downloads updated scripts from GitHub
\$RepoURL = 'https://raw.githubusercontent.com/YOURORG/YOURREPO/main/'
\$ScriptList = 'scripts.json'

\$localScriptPath = '$basePath\Scripts'
\$localScriptJson = Join-Path \$localScriptPath 'scripts.json'

Invoke-WebRequest -Uri "\$RepoURL\$ScriptList" -OutFile \$localScriptJson

\$scripts = (Get-Content -Path \$localScriptJson | ConvertFrom-Json).scripts
foreach (\$script in \$scripts) {
    \$scriptUrl = "\$RepoURL\$script"
    Invoke-WebRequest -Uri \$scriptUrl -OutFile (Join-Path \$localScriptPath \$script) -UseBasicParsing
}
"@
Set-Content -Path "$basePath\Scripts\Download-IntuneScriptsFromGithub.ps1" -Value $downloadScript -Force

# Create Scheduled Task (Run at Logon as USER)
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$basePath\Scripts\POSLockdown.ps1`""
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -RunLevel Highest
Register-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -TaskName "SSA_POSLockdown" -Description "Enforces device lockdown based on Azure group" -Force

# Initial Script Pull
Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$basePath\Scripts\Download-IntuneScriptsFromGithub.ps1`"" -Wait

# Done
Write-Output "SSA System setup complete."
