$scriptPath = "C:\ProgramData\POSControl\ToggleSettingsAccessByRole.ps1"

# Ensure folder exists
New-Item -Path "C:\ProgramData\POSControl" -ItemType Directory -Force | Out-Null

# Save the policy script to disk
@"
<PASTE YOUR TOGGLE SCRIPT HERE>
"@ | Out-File -FilePath $scriptPath -Encoding UTF8 -Force

# Register task to run at logon for all users
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`""
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\INTERACTIVE" -LogonType Interactive
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName "ToggleSettingsAccess" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
