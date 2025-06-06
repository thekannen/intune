# GLOBAL: Restrict Settings for all users via HKLM
$globalRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"

if (-not (Test-Path $globalRegPath)) {
    New-Item -Path $globalRegPath -Force | Out-Null
}

# Hide all settings pages
Set-ItemProperty -Path $globalRegPath -Name "SettingsPageVisibility" -Value "hide:*"

Write-Host "Global Settings restriction applied via HKLM"