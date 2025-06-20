# ------------------------------
# POSApplyUserLockdown.ps1
# ------------------------------
# SYSTEM-context script to apply or clear lockdown based on per-user SID cache and matrix.
# Works uniformly on Windows 10 & 11.
# ------------------------------

$tenantId   = '31424738-b78c-4273-b299-844512ee2746'
$clientId   = '231165ef-2a5c-4136-987f-4835086c089e'
$secretPath = "C:\ProgramData\SSA\Secrets\GraphApiCred.dat"
$matrixPath = "C:\ProgramData\SSA\Scripts\LockdownMatrix.json"
$queuePath  = "C:\ProgramData\SSA\LockdownQueue"
$logFilePath = "C:\ProgramData\SSA\Logs\POSLockdownSystem.log"

function Write-Log {
    param([string]$Message)
    $folder = Split-Path $logFilePath
    if (!(Test-Path $folder)) { New-Item -Path $folder -ItemType Directory -Force | Out-Null }
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
            Write-Log "[ERROR] Failed to decrypt client secret: $($_.Exception.Message)"
            return $null
        }
    } else {
        Write-Log "[ERROR] Client secret file not found at $secretPath"
        return $null
    }
}

function Get-GraphUserInfo($username) {
    try {
        $clientSecret = Get-ClientSecret
        if (!$clientSecret) { return $null }

        $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method POST -Body @{
            client_id     = $clientId
            scope         = "https://graph.microsoft.com/.default"
            client_secret = $clientSecret
            grant_type    = "client_credentials"
        }
        $token = $tokenResponse.access_token
        $upn = "$username@thessagroup.com"
        $userInfo = Invoke-RestMethod -Headers @{Authorization = "Bearer $token"} `
            -Uri "https://graph.microsoft.com/v1.0/users/$upn" `
            -Method Get
        return $userInfo
    } catch {
        Write-Log "[ERROR] Failed to get user info from Graph for $username: $($_.Exception.Message)"
        return $null
    }
}

function Get-MostRestrictivePolicy {
    # Everything set to true (most restricted)
    return @{
        NoClose = $true
        NoControlPanel = $true
        NoEdge = $true
    }
}

# Main Loop
Get-ChildItem -Path $queuePath -Filter '*.txt' -ErrorAction SilentlyContinue | ForEach-Object {
    $sid = $_.BaseName
    $decision = (Get-Content $_.FullName -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
    Write-Log "[INFO] Processing SID=$sid; Decision=$decision"

    if ($decision -eq 'EXEMPT') {
        Write-Log "[INFO] [$sid] Admin detected. No lockdown applied."
        return
    }

    # Default: most restrictive policy in case of failure
    $policy = Get-MostRestrictivePolicy
    $unit = "Unknown"
    $role = "Unknown"
    $username = $null

    # Try to get username for SID (from registry, fallback to sid)
    try {
        $userKey = "Registry::HKEY_USERS\$sid\Volatile Environment"
        if (Test-Path $userKey) {
            $username = (Get-ItemProperty -Path $userKey -Name USERNAME -ErrorAction Stop).USERNAME
        } else {
            Write-Log "[WARN] Could not find username for SID=$sid; using SID as fallback"
            $username = $sid
        }
    } catch {
        Write-Log "[WARN] Could not resolve username for SID=$sid: $($_.Exception.Message)"
        $username = $sid
    }

    # Get company and jobtitle if possible
    $userInfo = Get-GraphUserInfo $username
    if ($userInfo -and $userInfo.companyName -and $userInfo.jobTitle) {
        $unit = $userInfo.companyName
        $role = $userInfo.jobTitle
        Write-Log "[INFO] [$sid] User attributes: companyName=$unit, jobTitle=$role"
    } else {
        Write-Log "[WARN] [$sid] Could not get companyName or jobTitle, using most restrictive policy."
    }

    # Try to load the lockdown matrix and get correct policy
    if (Test-Path $matrixPath) {
        try {
            $matrix = Get-Content $matrixPath | ConvertFrom-Json
            if ($matrix.PSObject.Properties.Name -contains $unit -and $matrix.$unit.PSObject.Properties.Name -contains $role) {
                $policy = $matrix.$unit.$role
                Write-Log "[INFO] [$sid] Found lockdown policy in matrix for $unit/$role"
            } else {
                Write-Log "[WARN] [$sid] No policy in matrix for $unit/$role; using most restrictive"
            }
        } catch {
            Write-Log "[ERROR] [$sid] Failed to parse lockdown matrix: $($_.Exception.Message)"
        }
    } else {
        Write-Log "[ERROR] [$sid] Lockdown matrix not found at $matrixPath"
    }

    # Apply the lockdown policy
    $regPath = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    foreach ($setting in $policy.GetEnumerator()) {
        $name = $setting.Key
        $value = $setting.Value
        try {
            if ($value) {
                Set-ItemProperty -Path $regPath -Name $name -Value 1 -Type DWord -Force
                Write-Log "[INFO] [$sid] Applied: $name=1"
            } else {
                Remove-ItemProperty -Path $regPath -Name $name -ErrorAction SilentlyContinue
                Write-Log "[INFO] [$sid] Removed: $name"
            }
        } catch {
            Write-Log "[ERROR] [$sid] Failed to set $name: $($_.Exception.Message)"
        }
    }
    Write-Log "[INFO] [$sid] Lockdown applied for $unit/$role."
}
