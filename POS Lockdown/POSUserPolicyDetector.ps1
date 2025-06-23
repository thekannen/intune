# ------------------------------
# POSUserPolicyDetector.ps1
# ------------------------------

<#
  - Ensures LockdownQueue folder exists
  - Retrieves user company and role via Graph API
  - Writes robust, logged queue file
  - Includes startup delay to ensure sequential execution
#>

# Configuration
$tenantId    = '31424738-b78c-4273-b299-844512ee2746'
$clientId    = '231165ef-2a5c-4136-987f-4835086c089e'
$secretPath  = "C:\ProgramData\SSA\Secrets\GraphApiCred.dat"
$cacheDir    = "C:\ProgramData\SSA\LockdownQueue"
$logFilePath = "C:\ProgramData\SSA\Logs\POSUserPolicyDetector.log"

# Delay to allow upstream processes to complete
Start-Sleep -Seconds 5

# Logging function
default param
function Write-Log {
    param([string]$Message)
    $folder = Split-Path $logFilePath
    if (-not (Test-Path $folder)) { New-Item -Path $folder -ItemType Directory -Force | Out-Null }
    "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) - $Message" |
        Out-File -FilePath $logFilePath -Append -Encoding utf8
}

# 0) Ensure cache directory exists
if (-not (Test-Path $cacheDir)) {
    try {
        New-Item -Path $cacheDir -ItemType Directory -Force | Out-Null
        Write-Log "[INFO] Created LockdownQueue directory at $cacheDir"
    } catch {
        Write-Log "[ERROR] Could not create LockdownQueue directory: $($_.Exception.Message)"
        throw
    }
}

# Helper: decrypt client secret
function Get-ClientSecret {
    if (Test-Path $secretPath) {
        try {
            Add-Type -AssemblyName System.Security
            $b64       = Get-Content -Path $secretPath -Raw
            $encrypted = [Convert]::FromBase64String($b64)
            $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect(
                $encrypted, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine
            )
            return [System.Text.Encoding]::UTF8.GetString($decrypted)
        } catch {
            Write-Log "[ERROR] Failed to decrypt client secret: $($_.Exception.Message)"
            return $null
        }
    } else {
        Write-Log "[ERROR] Client secret file not found at $secretPath"
        return $null
    }
}

# Main
try {
    $userSid  = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    $username = $env:USERNAME
    $upn      = "$username@thessagroup.com"
    $queueFile = Join-Path $cacheDir "$userSid.txt"

    Write-Log "[INFO] Starting policy detection for $username (SID: $userSid)"

    # Get client secret
    $clientSecret = Get-ClientSecret
    if (-not $clientSecret) { throw "No client secret available" }

    # Acquire Graph token
    $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method POST -Body @{
        client_id     = $clientId
        scope         = "https://graph.microsoft.com/.default"
        client_secret = $clientSecret
        grant_type    = "client_credentials"
    }
    $token = $tokenResponse.access_token
    Write-Log "[INFO] Acquired Graph access token"

    # Query user object
    $headers  = @{ Authorization = "Bearer $token" }
    $userInfo = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$upn?`$select=companyName,jobTitle" -Headers $headers -Method GET

    $company = $userInfo.companyName
    $role    = $userInfo.jobTitle
    if (-not $company) { $company = 'Unknown' }
    if (-not $role)    { $role    = 'Unknown' }

    # 3) Write queue file with full logging
    $content = @(
        "company: $company",
        "role:    $role"
    )
    Write-Log "[INFO] About to write queue file for SID=$userSid:`n    $($content -join "`n    ")"
    $content | Out-File -FilePath $queueFile -Encoding ASCII -Force

    if (Test-Path $queueFile) {
        $dump = (Get-Content $queueFile) -join "; "
        Write-Log "[INFO] Queue file contents: $dump"
    } else {
        Write-Log "[ERROR] Queue file was NOT created at $queueFile!"
    }
}
catch {
    Write-Log "[ERROR] Detection failed: $($_.Exception.Message)"
}
