Start-Transcript -Path "C:\ProgramData\SSA\Logs\LastRunTranscript.log" -Append

# ------------------------------
# POSUserPolicyDetector.ps1
# ------------------------------
# Detects user group, company, role and writes JSON decision for use by lockdown script

$tenantId      = '31424738-b78c-4273-b299-844512ee2746'
$clientId      = '231165ef-2a5c-4136-987f-4835086c089e'
$posGroupId    = 'b1b0549e-92fa-4610-b058-611e440a4367'
$adminExemptId = '6e615bdf-799a-405f-98ad-67fbf16a996b'
$secretPath    = "C:\ProgramData\SSA\Secrets\GraphApiCred.dat"

$userSid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
$username = $env:USERNAME
$domain = $env:USERDOMAIN
$upn = "$username@thessagroup.com"

$cacheDir    = "C:\ProgramData\SSA\LockdownQueue"
$logFilePath = "C:\ProgramData\SSA\Logs\POSUserPolicyDetector.log"
$cachePath   = Join-Path $cacheDir "$userSid.txt"

function Write-Log {
    param([string]$Message)
    $logFolder = Split-Path $logFilePath
    if (-not (Test-Path $logFolder)) { New-Item -Path $logFolder -ItemType Directory -Force | Out-Null }
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

function Write-DecisionToCache($obj) {
    try {
        $json = $obj | ConvertTo-Json -Compress
        $json | Out-File -FilePath $cachePath -Encoding utf8 -Force
        Write-Log "[INFO] Decision cached at $cachePath: $json"
    } catch {
        Write-Log "[ERROR] Failed to write decision to cache: $($_.Exception.Message)"
    }
}

Write-Log "[INFO] Policy detection started for $username (SID: $userSid, Domain: $domain)"

if ($domain -eq $env:COMPUTERNAME) {
    Write-Log "[INFO] Detected local account. Falling back to local group detection."
    try {
        $groupOutput = whoami /groups
        if ($groupOutput -match "Administrators") {
            Write-DecisionToCache @{ status = "EXEMPT" }
            return
        } else {
            Write-DecisionToCache @{ status = "LOCKDOWN"; company = "Unknown"; role = "Unknown" }
            return
        }
    } catch {
        Write-Log "[WARN] Could not check local group: $($_.Exception.Message)"
        Write-DecisionToCache @{ status = "LOCKDOWN"; company = "Unknown"; role = "Unknown" }
        return
    }
}

# Azure AD user check
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

    if ($response.value -contains $adminExemptId) {
        Write-DecisionToCache @{ status = "EXEMPT" }
        return
    } elseif ($response.value -contains $posGroupId) {
        # Get company and job title for this user
        try {
            $userInfo = Invoke-RestMethod -Headers @{Authorization = "Bearer $token"} `
                -Uri "https://graph.microsoft.com/v1.0/users/$upn" `
                -Method Get
            $unit = $userInfo.companyName
            $role = $userInfo.jobTitle
            if ([string]::IsNullOrWhiteSpace($unit) -or [string]::IsNullOrWhiteSpace($role)) {
                Write-Log "[WARN] User $upn missing companyName or jobTitle in Entra. Defaulting to most restrictive."
                Write-DecisionToCache @{ status = "LOCKDOWN"; company = "Unknown"; role = "Unknown" }
            } else {
                Write-Log "[INFO] $username mapped to company='$unit', role='$role'."
                Write-DecisionToCache @{ status = "LOCKDOWN"; company = $unit; role = $role }
            }
        } catch {
            Write-Log "[ERROR] Failed to fetch company/role for $username: $($_.Exception.Message)"
            Write-DecisionToCache @{ status = "LOCKDOWN"; company = "Unknown"; role = "Unknown" }
        }
        return
    } else {
        Write-DecisionToCache @{ status = "NONE" }
        return
    }
} catch {
    Write-Log "[WARN] Graph query failed: $($_.Exception.Message)"
    Write-DecisionToCache @{ status = "LOCKDOWN"; company = "Unknown"; role = "Unknown" }
}
Stop-Transcript
