# ------------------------------
# POSUserPolicyDetector.ps1
# ------------------------------

# Configuration
$tenantId   = '31424738-b78c-4273-b299-844512ee2746'
$clientId   = '231165ef-2a5c-4136-987f-4835086c089e'
$secretPath = "C:\ProgramData\SSA\Secrets\GraphApiCred.dat"
$cacheDir   = "C:\ProgramData\SSA\LockdownQueue"
$logFilePath= "C:\ProgramData\SSA\Logs\POSUserPolicyDetector.log"

$userSid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
$username = $env:USERNAME
$upn = "$username@thessagroup.com"
$queueFile = Join-Path $cacheDir "$userSid.txt"

function Write-Log {
    param([string]$Message)
    $logFolder = Split-Path $logFilePath
    if (-not (Test-Path $logFolder)) {
        New-Item -Path $logFolder -ItemType Directory -Force | Out-Null
    }
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
            Write-Log "ERROR: Failed to decrypt client secret: $($_.Exception.Message)"
            return $null
        }
    } else {
        Write-Log "ERROR: Client secret file not found at $secretPath"
        return $null
    }
}

# Main
try {
    $clientSecret = Get-ClientSecret
    if (!$clientSecret) { throw "No client secret" }

    $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method POST -Body @{
        client_id     = $clientId
        scope         = "https://graph.microsoft.com/.default"
        client_secret = $clientSecret
        grant_type    = "client_credentials"
    }
    $token = $tokenResponse.access_token

    $headers = @{ Authorization = "Bearer $token" }
    $userInfo = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$upn" -Headers $headers -Method GET

    $company = $userInfo.companyName
    $role    = $userInfo.jobTitle

    if (-not $company) { $company = "Unknown" }
    if (-not $role)    { $role    = "Unknown" }

    # Write out queue file
    @(
        "company: $company"
        "role: $role"
    ) | Out-File -FilePath $queueFile -Encoding ASCII -Force

    Write-Log "Wrote queue file for `${userSid}`: company=$company, role=$role"
} catch {
    Write-Log "ERROR: $($_.Exception.Message)"
}
