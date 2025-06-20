# ------------------------------
# POSUserPolicyDetector.ps1
# ------------------------------
# This script is intended to run at user logon.
# It determines if the user is an admin or a regular user.
# For regular users, it looks up their company and job title from Entra ID (Azure AD) via Graph API.
# It then caches a decision file per-user SID in LockdownQueue for the lockdown script to use.

# ----- Configuration -----
$tenantId   = '31424738-b78c-4273-b299-844512ee2746' # Azure tenant ID
$clientId   = '231165ef-2a5c-4136-987f-4835086c089e' # Graph API application client ID
$secretPath = "C:\ProgramData\SSA\Secrets\GraphApiCred.dat" # Encrypted client secret file path
$domain     = 'thessagroup.com'   # User domain

# ----- Paths -----
$cacheDir    = "C:\ProgramData\SSA\LockdownQueue" # Where per-user decision files are stored
$logFilePath = "C:\ProgramData\SSA\Logs\POSUserPolicyDetector.log" # Log output file path
$userSid     = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value # Current user SID
$cachePath   = Join-Path $cacheDir "$userSid.json" # Path for this user's decision cache
$username    = $env:USERNAME # Username of the currently logged-in user

# ----- Function: Write-Log -----
# Logs a message to the detector's log file (auto-creates folder if missing)
function Write-Log {
    param([string]$Message)
    $logFolder = Split-Path $logFilePath
    if (-not (Test-Path $logFolder)) {
        New-Item -Path $logFolder -ItemType Directory -Force | Out-Null
    }
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "$timestamp - $Message" | Out-File -FilePath $logFilePath -Append -Encoding utf8
}

# ----- Function: Get-ClientSecret -----
# Reads and decrypts the Graph API client secret stored on disk for this device
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

# ----- Function: Write-DecisionToCache -----
# Stores the current decision (EXEMPT or LOCKDOWN) in the per-user SID JSON file
function Write-DecisionToCache($decision) {
    try {
        $decision | ConvertTo-Json | Set-Content -Path $cachePath -Encoding UTF8 -Force
        Write-Log "[INFO] Decision cached at $cachePath: $($decision | ConvertTo-Json -Compress)"
    } catch {
        Write-Log "[ERROR] Failed to write decision to cache: $($_.Exception.Message)"
    }
}

# ======= Main Logic =======

# 1. Check for admin group membership (EXEMPT)
try {
    $groupOutput = whoami /groups
    if ($groupOutput -match "Administrators") {
        $decision = @{ Status = "EXEMPT" }
        Write-DecisionToCache $decision
        Write-Log "[INFO] Admin group detected for $username. User is exempt."
        return # Stop here for admin users (no lockdown applied)
    }
} catch {
    Write-Log "[WARN] Could not check admin group: $($_.Exception.Message)"
}

# 2. For regular users, look up company and job title from Entra ID (Graph API)
$upn = "$username@$domain"
try {
    $clientSecret = Get-ClientSecret

    # Authenticate to Graph API and get access token
    $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method POST -Body @{
        client_id     = $clientId
        scope         = "https://graph.microsoft.com/.default"
        client_secret = $clientSecret
        grant_type    = "client_credentials"
    }
    $token = $tokenResponse.access_token

    # Retrieve user object from Graph API (companyName, jobTitle)
    $userInfo = Invoke-RestMethod -Headers @{Authorization = "Bearer $token"} `
        -Uri "https://graph.microsoft.com/v1.0/users/$upn" `
        -Method Get

    $unit = $userInfo.companyName
    $role = $userInfo.jobTitle

    # If user has no company or role set, default to Unknown and apply most restrictive
    if ([string]::IsNullOrWhiteSpace($unit) -or [string]::IsNullOrWhiteSpace($role)) {
        Write-Log "[WARN] User $upn missing companyName or jobTitle in Entra. Defaulting to most restrictive."
        $decision = @{ Status = "LOCKDOWN"; Unit = "Unknown"; Role = "Unknown" }
    } else {
        $decision = @{ Status = "LOCKDOWN"; Unit = $unit; Role = $role }
        Write-Log "[INFO] $username mapped to Unit='$unit', Role='$role'."
    }

    # Cache decision for this user
    Write-DecisionToCache $decision
} catch {
    Write-Log "[WARN] Failed to get user attributes from Graph for $username: $($_.Exception.Message)"
    $decision = @{ Status = "LOCKDOWN"; Unit = "Unknown"; Role = "Unknown" }
    Write-DecisionToCache $decision
}
