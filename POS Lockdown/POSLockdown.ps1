# -------------------------------------------------------
# Per-user lockdown script: restrict POS users at logon,
# exempt admin group users. Apply at every user logon.
# -------------------------------------------------------

# CONFIGURATION (fill in your actual values)
$tenantId          = 'REDACTED'
$clientId          = 'REDACTED'
$clientSecret      = 'REDACTED'
$posGroupId        = 'REDACTED'
$adminExemptId     = 'REDACTED'

try {
    # --- 1. Get Graph API token (client credentials) ---
    Write-Host "Getting Graph API token..."
    $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method POST -Body @{
        client_id     = $clientId
        scope         = "https://graph.microsoft.com/.default"
        client_secret = $clientSecret
        grant_type    = "client_credentials"
    }
    $token = $tokenResponse.access_token
    Write-Host "Token acquired."

    # --- 2. Check group membership for current user ---
    $upn = "$env:USERNAME@thessagroup.com"
    Write-Host "Checking group membership for $upn ..."
    $body = @{ groupIds = @($posGroupId, $adminExemptId) } | ConvertTo-Json
    $headers = @{
        Authorization = "Bearer $token"
        "Content-Type" = "application/json"
    }
    $result = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$upn/checkMemberGroups" -Method POST -Headers $headers -Body $body
    Write-Host "Graph API Result: $($result | Out-String)"

    # --- 3. Registry lockdown logic (per-user HKCU) ---
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

    # Helper: always reset first
    if (Test-Path $regPath) {
        Remove-ItemProperty -Path $regPath -Name NoClose        -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $regPath -Name NoControlPanel -ErrorAction SilentlyContinue
    }

    # Helper: set lockdown if needed
    function Set-POSLockdown {
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        Set-ItemProperty -Path $regPath -Name NoClose         -Value 1 -Type DWord      # Hide shutdown/restart
        Set-ItemProperty -Path $regPath -Name NoControlPanel  -Value 1 -Type DWord      # Block Control Panel & Settings (blocks network too)
    }

    # --- 4. Apply correct lockdown based on group membership ---
    if ($result.value -contains $adminExemptId) {
        Write-Host "User is in Admin Exempt Group: unrestricted."
    }
    elseif ($result.value -contains $posGroupId) {
        Set-POSLockdown
        Write-Host "User is in POS Group: lockdown applied."
    }
    else {
        Write-Host "User is not in POS or Admin Exempt Group: unrestricted."
    }
}
catch {
    Write-Host "`nERROR: $($_.Exception.Message)"
}

Write-Host "`nScript finished. Press Enter to close."
Read-Host