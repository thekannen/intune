# ------------------------------
# POSUserPolicyDetector.ps1 - Minimal JSON Test Version
# ------------------------------

$tenantId      = '31424738-b78c-4273-b299-844512ee2746'
$clientId      = '231165ef-2a5c-4136-987f-4835086c089e'
$secretPath    = "C:\ProgramData\SSA\Secrets\GraphApiCred.dat"

$userSid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
$username = $env:USERNAME
$domain = $env:USERDOMAIN
$upn = "$username@thessagroup.com"

$cacheDir  = "C:\ProgramData\SSA\LockdownQueue"
$logFilePath   = "C:\ProgramData\SSA\Logs\POSUserPolicyDetector.log"
$cachePath = Join-Path $cacheDir "$userSid.json"

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
            Write-Log "[ERROR] Failed to decrypt client secret: $($_.Exception.Message)"
            return $null
        }
    } else {
        Write-Log "[ERROR] Client secret file not found at $secretPath"
        return $null
    }
}

function Write-DecisionToCache($decision) {
    try {
        $decision | ConvertTo-Json | Set-Content -Path $cachePath -Encoding UTF8 -Force
        Write-Log "[INFO] Decision cached at $cachePath: $($decision | ConvertTo-Json -Compress)"
    } catch {
        Write-Log "[ERROR] Failed to write decision to cache: $($_.Exception.Message)"
    }
}

# --------- Main Logic ---------
try {
    $groupOutput = whoami /groups
    if ($groupOutput -match "Administrators") {
        $decision = @{ Status = "EXEMPT" }
        Write-DecisionToCache $decision
        Write-Log "[INFO] Admin group detected for $username. User is exempt."
        return
    }
} catch {
    Write-Log "[WARN] Could not check admin group: $($_.Exception.Message)"
}

try {
    $clientSecret = Get-ClientSecret
    if (!$clientSecret) { throw "No client secret!" }

    $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method POST -Body @{
        client_id     = $clientId
        scope         = "https://graph.microsoft.com/.default"
        client_secret = $clientSecret
        grant_type    = "client_credentials"
    }
    $token = $tokenResponse.access_token

    $userInfo = Invoke-RestMethod -Headers @{Authorization = "Bearer $token"} `
        -Uri "https://graph.microsoft.com/v1.0/users/$upn" `
        -Method Get

    $unit = $userInfo.companyName
    $role = $userInfo.jobTitle

    if ([string]::IsNullOrWhiteSpace($unit) -or [string]::IsNullOrWhiteSpace($role)) {
        Write-Log "[WARN] User $upn missing companyName or jobTitle in Entra. Defaulting to most restrictive."
        $decision = @{ Status = "LOCKDOWN"; Unit = "Unknown"; Role = "Unknown" }
    } else {
        $decision = @{ Status = "LOCKDOWN"; Unit = $unit; Role = $role }
        Write-Log "[INFO] $username mapped to Unit='$unit', Role='$role'."
    }
    Write-DecisionToCache $decision
} catch {
    Write-Log "[ERROR] Failed to get user attributes or write decision: $($_.Exception.Message)"
    $decision = @{ Status = "LOCKDOWN"; Unit = "Unknown"; Role = "Unknown" }
    Write-DecisionToCache $decision
}
