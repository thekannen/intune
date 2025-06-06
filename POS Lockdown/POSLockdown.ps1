# -------------------------------------------------------
# Per-user lockdown script: restrict POS users at logon,
# exempt admin group users. Apply at every user logon.
# -------------------------------------------------------

# --- CONFIGURATION SECTION ---

# Azure AD / Graph API settings (safe to leave in script)
$tenantId          = '31424738-b78c-4273-b299-844512ee2746'
$clientId          = '231165ef-2a5c-4136-987f-4835086c089e'
$posGroupId        = 'b1b0549e-92fa-4610-b058-611e440a4367'
$adminExemptId     = '6e615bdf-799a-405f-98ad-67fbf16a996b'

# Client Secret File
$secretPath = "C:\ProgramData\SSA\Secrets\GraphApiCred.txt"

# Dynamic lockdown toggles
$LockdownSettings = @{
    NoClose         = $true  # Disable Shutdown / Restart
    NoControlPanel  = $true  # Disable Control Panel / Settings access
    # Add more settings here if needed later
}

# Log file setup
$logFilePath = "C:\ProgramData\SSA\Logs\POSLockdownLog.txt"

# Registry path for HKCU policies
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

# --- FUNCTIONS ---

# Safely read client secret
function Get-ClientSecret {
    if (Test-Path $secretPath) {
        return Get-Content -Path $secretPath -ErrorAction Stop
    } else {
        throw "Client secret file not found at $secretPath."
    }
}

# Obtain Graph API Token
function Get-GraphApiToken {
    param (
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret
    )
    $body = @{
        client_id     = $ClientId
        scope         = "https://graph.microsoft.com/.default"
        client_secret = $ClientSecret
        grant_type    = "client_credentials"
    }
    $response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body $body
    return $response.access_token
}

# Apply or remove lockdown
function Set-POSLockdown {
    param (
        [bool]$Enable
    )

    Write-Log "Starting Set-POSLockdown function. Enable = $Enable"

    if (-not (Test-Path $regPath)) {
        try {
            New-Item -Path $regPath -Force | Out-Null
            Write-Log "Created registry path: $regPath"
        } catch {
            Write-Log "ERROR creating registry path $regPath : $($_.Exception.Message)"
        }
    } else {
        Write-Log "Registry path already exists: $regPath"
    }

    if ($Enable) {
        foreach ($setting in $LockdownSettings.Keys) {
            if ($LockdownSettings[$setting]) {
                try {
                    Set-ItemProperty -Path $regPath -Name $setting -Value 1 -Type DWord -Force
                    Write-Log "Applied registry setting: $setting = 1"
                } catch {
                    Write-Log "ERROR applying setting $setting : $($_.Exception.Message)"
                }
            } else {
                Write-Log "Skipping setting $setting because it's disabled in LockdownSettings."
            }
        }
    } else {
        foreach ($setting in $LockdownSettings.Keys) {
            try {
                if (Get-ItemProperty -Path $regPath -Name $setting -ErrorAction Stop) {
                    Remove-ItemProperty -Path $regPath -Name $setting -ErrorAction SilentlyContinue
                    Write-Log "Removed registry setting: $setting"
                }
            } catch {
                Write-Log "Setting $setting does not exist, skipping removal."
            }
        }
    }

    Write-Log "Set-POSLockdown function completed."
}

function Write-Log {
    param([string]$Message)

    $logFolder = Split-Path $logFilePath
    if (-not (Test-Path $logFolder)) {
        New-Item -Path $logFolder -ItemType Directory -Force | Out-Null
    }

    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "$timestamp - $Message" | Out-File -FilePath $logFilePath -Append -Encoding utf8
}

# --- MAIN SCRIPT LOGIC ---

try {
    # Read secret and get token
    $clientSecret = Get-ClientSecret
    Write-Log "Obtaining Graph API token..."
    $token = Get-GraphApiToken -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecret
    Write-Log "Token acquired."

    # Check group membership
    $upn = "$env:USERNAME@thessagroup.com"  # <-- replace with your UPN domain
    Write-Log "Checking group membership for $upn ..."
    $body = @{ groupIds = @($posGroupId, $adminExemptId) } | ConvertTo-Json
    $headers = @{
        Authorization = "Bearer $token"
        "Content-Type" = "application/json"
    }
    $result = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$upn/checkMemberGroups" -Method POST -Headers $headers -Body $body
    Write-Log "Group check result: $($result.value -join ', ')"

    # Apply lockdown logic
    if ($result.value -contains $adminExemptId) {
        Write-Log "User is in Admin Exempt Group: unrestricted access."
        Set-POSLockdown -Enable:$false
    }
    elseif ($result.value -contains $posGroupId) {
        Write-Log "User is in POS Group: lockdown applied."
        Set-POSLockdown -Enable:$true
    }
    else {
        Write-Log "User is not in POS or Admin Exempt Group: unrestricted access."
        Set-POSLockdown -Enable:$false
    }
}
catch {
    Write-Log "ERROR: $($_.Exception.Message)"
}

# --- END ---