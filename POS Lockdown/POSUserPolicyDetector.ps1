# ------------------------------
# POSUserPolicyDetector.ps1
# ------------------------------
# Runs in user context at logon
# Queries Microsoft Graph and caches lockdown decision for SYSTEM task to act on
# ------------------------------

# Configuration
$tenantId          = '31424738-b78c-4273-b299-844512ee2746'
$clientId          = '231165ef-2a5c-4136-987f-4835086c089e'
$posGroupId        = 'b1b0549e-92fa-4610-b058-611e440a4367'
$adminExemptId     = '6e615bdf-799a-405f-98ad-67fbf16a996b'

# Client Secret File
$secretPath = "C:\ProgramData\SSA\Secrets\GraphApiCred.txt"

# Detect current user SID and UPN
$userSid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
$upn = "$env:USERNAME@thessagroup.com"

# Location to cache lockdown decision for SYSTEM script
$cacheDir = "C:\ProgramData\SSA\LockdownQueue"
$cachePath = Join-Path $cacheDir "$userSid.txt"

# Ensure cache dir exists
if (-not (Test-Path $cacheDir)) {
    New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null
}

function Get-ClientSecret {
    if (Test-Path $secretPath) {
        $encrypted = Get-Content -Path $secretPath -Raw
        $secure = ConvertTo-SecureString $encrypted -Scope LocalMachine
        return [System.Net.NetworkCredential]::new("", $secure).Password
    } else {
        throw "Client secret file not found at $secretPath"
    }
}

try {
    # Read secret and get token
    $clientSecret = Get-ClientSecret

    # Get Graph API token
    $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method POST -Body @{
        client_id     = $clientId
        scope         = "https://graph.microsoft.com/.default"
        client_secret = $clientSecret
        grant_type    = "client_credentials"
    }
    $token = $tokenResponse.access_token

    # Check group membership
    $body = @{ groupIds = @($posGroupId, $adminExemptId) } | ConvertTo-Json
    $headers = @{
        Authorization = "Bearer $token"
        "Content-Type" = "application/json"
    }
    $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$upn/checkMemberGroups" -Method POST -Headers $headers -Body $body

    # Determine lockdown status
    $status = "NONE"
    if ($response.value -contains $adminExemptId) {
        $status = "EXEMPT"
    }
    elseif ($response.value -contains $posGroupId) {
        $status = "LOCKDOWN"
    }

    # Write decision to SID-named cache file
    $status | Out-File -FilePath $cachePath -Encoding ASCII -Force

    # Optional: tighten permissions (read/write SYSTEM only, deny users)
    $acl = Get-Acl $cachePath
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")
    $acl.SetAccessRule($rule)
    Set-Acl -Path $cachePath -AclObject $acl

} catch {
    "[ERROR] Failed to determine group membership: $($_.Exception.Message)" | Out-File "$cacheDir\Error_$userSid.log" -Append
}
