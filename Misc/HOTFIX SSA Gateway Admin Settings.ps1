# Loop through all user SIDs in HKEY_USERS
Get-ChildItem 'Registry::HKEY_USERS' | ForEach-Object {
    $sid = $_.PSChildName

    # Remove SettingsPageVisibility
    $settingsKey = "Registry::HKEY_USERS\$sid\Software\Policies\Microsoft\Windows\Explorer"
    if (Test-Path $settingsKey) {
        try {
            Remove-ItemProperty -Path $settingsKey -Name 'SettingsPageVisibility' -ErrorAction Stop
            Write-Host "Removed SettingsPageVisibility for SID: $sid"
        } catch {
            Write-Host "SettingsPageVisibility not set or error for SID: $sid - $($_.Exception.Message)"
        }
    }

    # Remove NoControlPanel
    $controlPanelKey = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    if (Test-Path $controlPanelKey) {
        try {
            Remove-ItemProperty -Path $controlPanelKey -Name 'NoControlPanel' -ErrorAction Stop
            Write-Host "Removed NoControlPanel for SID: $sid"
        } catch {
            Write-Host "NoControlPanel not set or error for SID: $sid - $($_.Exception.Message)"
        }
    }
}