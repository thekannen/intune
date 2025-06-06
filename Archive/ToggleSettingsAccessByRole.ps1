# ToggleSettingsAccessByRole.ps1
# Description:
#   - Detects whether the current user is an administrator
#   - If NOT an admin, it hides all Settings pages using the SettingsPageVisibility policy
#   - If the user IS an admin, it removes the policy restriction
#   - This script is meant to run in the context of the **logged-in user**
#     to modify their HKCU (user-specific) registry values

# Get the current logged-in user context
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$username = $currentUser.Name

# Check if the user has local admin privileges
$isAdmin = (New-Object Security.Principal.WindowsPrincipal $currentUser).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator
)

# Registry path to Explorer policies in current user hive
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

# --- Apply or remove Settings visibility restrictions based on role ---

if (-not $isAdmin) {
    # User is NOT an admin — hide all settings pages
    # Ensure the registry key exists
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    # Set the policy to hide all Settings pages
    Set-ItemProperty -Path $regPath -Name "SettingsPageVisibility" -Value "hide:*"
}
else {
    # User IS an admin — remove any visibility restriction
    if (Test-Path "$regPath\SettingsPageVisibility") {
        Remove-ItemProperty -Path $regPath -Name "SettingsPageVisibility" -ErrorAction SilentlyContinue
    }
}
