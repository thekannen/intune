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
    if (-not (Test-Path $logFolder)) {
        New-Item -Path $logFolder -ItemType Directory -Force | Out-Null
    }

    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "$timestamp - $Message" | Out-File -FilePath $logFilePath -Append -Encoding utf8
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

function Write-DecisionToCache($status) {
    try {
        $status | Out-File -FilePath $cachePath -Encoding ASCII -Force
        Write-Log "[INFO] [$status] Decision cached at $cachePath"
    } catch {
        Write-Log "[ERROR] Failed to write decision to cache: $($_.Exception.Message)"
    }
}

function DetectLocalGroup() {
    try {
        $groupOutput = whoami /groups
        if ($groupOutput -match "Administrators") {
            Write-Log "[INFO] Local group match found: Administrators"
            return "EXEMPT"
        }
        if ($groupOutput -match "Users") {
            Write-Log "[INFO] Local group match found: Users"
            return "LOCKDOWN"
        }        
    } catch {
        Write-Log "[WARN] Failed to check local group membership: $($_.Exception.Message)"
    }
    return "NONE"
}

# --- Main Logic ---
Write-Log "[INFO] Policy detection started for $username (SID: $userSid, Domain: $domain)"

# LOCAL ACCOUNT HANDLING
if ($domain -eq $env:COMPUTERNAME) {
    Write-Log "[INFO] Detected local account. Falling back to local group detection."
    $status = DetectLocalGroup
    Write-DecisionToCache $status
    return
}

try {
    $clientSecret = Get-ClientSecret
    Write-Log "[INFO] Client secret decrypted successfully."

    $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method POST -Body @{
        client_id     = $clientId
        scope         = "https://graph.microsoft.com/.default"
        client_secret = $clientSecret
        grant_type    = "client_credentials"
    }
    $token = $tokenResponse.access_token
    Write-Log "[INFO] Graph token acquired."

    $body = @{ groupIds = @($posGroupId, $adminExemptId) } | ConvertTo-Json
    $headers = @{
        Authorization = "Bearer $token"
        "Content-Type" = "application/json"
    }
    $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$upn/checkMemberGroups" -Method POST -Headers $headers -Body $body
    Write-Log "[INFO] Group membership result: $($response.value -join ', ')"

    $status = "NONE"
    if ($response.value -contains $adminExemptId) { $status = "EXEMPT" }
    elseif ($response.value -contains $posGroupId) { $status = "LOCKDOWN" }

    Write-DecisionToCache $status
}
catch {
    Write-Log "[WARN] Graph query failed: $($_.Exception.Message)"

    if (Test-Path $cachePath) {
        $cached = Get-Content $cachePath -ErrorAction SilentlyContinue | Select-Object -First 1
        Write-Log "[INFO] Graph offline. Falling back to cached decision: $cached"
    } else {
        Write-Log "[INFO] No cache available. Defaulting to NONE"
        $cached = "NONE"
    }
    Write-DecisionToCache $cached
}
