# Detect logged-in user and role
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$username = $currentUser.Name
$isAdmin = (New-Object Security.Principal.WindowsPrincipal $currentUser).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

# Registry path to modify
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

# Apply restrictions
if (-not $isAdmin) {
    # Create key if it doesn't exist
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "SettingsPageVisibility" -Value "hide:*"
} else {
    # Remove restriction for admins
    if (Test-Path "$regPath\SettingsPageVisibility") {
        Remove-ItemProperty -Path $regPath -Name "SettingsPageVisibility" -ErrorAction SilentlyContinue
    }
}
