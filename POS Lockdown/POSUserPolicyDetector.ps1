# ------------------------------
# POSUserPolicyDetector.ps1
# ------------------------------

# Configuration
$tenantId      = '31424738-b78c-4273-b299-844512ee2746'
$clientId      = '231165ef-2a5c-4136-987f-4835086c089e'
$posGroupId    = 'b1b0549e-92fa-4610-b058-611e440a4367'
$adminExemptId = '6e615bdf-799a-405f-98ad-67fbf16a996b'
$secretPath    = "C:\ProgramData\SSA\Secrets\GraphApiCred.dat"

# Detect user info
$userSid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
$username = $env:USERNAME
$domain = $env:USERDOMAIN
$upn = "$username@thessagroup.com"

# Paths
$cacheDir  = "C:\ProgramData\SSA\LockdownQueue"
$logFilePath   = "C:\ProgramData\SSA\Logs\POSUserPolicyDetector.log"
$cachePath = Join-Path $cacheDir "$userSid.txt"

# --- Logging function ---
function Write-Log {
    param([string]$Message)
    $logFolder = Split-Path $logFilePath
    if (-not (Test-Path $logFolder)) { New-Item -Path $logFolder -ItemType Directory -Force | Out-Null }
    "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) - $Message" | Out-File -FilePath $logFilePath -Append -Encoding utf8
}

function Get-ClientSecret {
    if (Test-Path $secretPath) {
        try {
            Add-Type -AssemblyName System.Security
            $b64 = Get-Content -Path $secretPath -Raw
            $encrypted = [Convert]::FromBase64String($b64)
            $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect(
                $encrypted, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine
            )
            return [System.Text.Encoding]::UTF8.GetString($decrypted)
        } catch {
            throw "Failed to decrypt client secret: $($_.Exception.Message)"
        }
    } else {
        throw "Client secret file not found at $secretPath"
    }
}

function Write-DecisionToCache($obj) {
    try {
        $obj | ConvertTo-Json | Set-Content -Path $cachePath -Encoding UTF8 -Force
        Write-Log "[INFO] Decision cached at $cachePath: $($obj | ConvertTo-Json -Compress)"
    } catch {
        Write-Log "[ERROR] Failed to write decision to cache: $($_.Exception.Message)"
    }
}

# --- Main Logic ---
Write-Log "[INFO] Policy detection started for $username (SID: $userSid, Domain: $domain)"

# 1. Exempt if admin
try {
    $groupOutput = whoami /groups
    if ($groupOutput -match "Administrators") {
        Write-DecisionToCache @{ Status = "EXEMPT" }
        Write-Log "[INFO] Admin group detected. Exempted."
        return
    }
} catch {
    Write-Log "[WARN] Could not check admin group: $($_.Exception.Message)"
}

# 2. If not admin, check group, company, and role from Graph
try {
    $clientSecret = Get-ClientSecret
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

    if ($response.value -contains $adminExemptId) {
        Write-DecisionToCache @{ Status = "EXEMPT" }
        Write-Log "[INFO] $username in admin exempt group. Exempted."
        return
    } elseif ($response.value -contains $posGroupId) {
        # Now get companyName and jobTitle for this user
        $userInfo = Invoke-RestMethod -Headers @{Authorization = "Bearer $token"} `
            -Uri "https://graph.microsoft.com/v1.0/users/$upn" `
            -Method Get
        $unit = $userInfo.companyName
        $role = $userInfo.jobTitle
        if ([string]::IsNullOrWhiteSpace($unit) -or [string]::IsNullOrWhiteSpace($role)) {
            Write-Log "[WARN] User missing companyName or jobTitle, using defaults for lockdown"
            Write-DecisionToCache @{ Status = "LOCKDOWN"; Unit = "Unknown"; Role = "Unknown" }
        } else {
            Write-DecisionToCache @{ Status = "LOCKDOWN"; Unit = $unit; Role = $role }
            Write-Log "[INFO] User mapped to Unit='$unit', Role='$role'"
        }
        return
    } else {
        Write-DecisionToCache @{ Status = "NONE" }
        Write-Log "[INFO] User not in any managed group. No lockdown applied."
        return
    }
} catch {
    Write-Log "[ERROR] Graph query failed: $($_.Exception.Message)"
    Write-DecisionToCache @{ Status = "LOCKDOWN"; Unit = "Unknown"; Role = "Unknown" }
}
