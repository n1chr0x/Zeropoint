# Filename: Detect-SharePoint-CVE-2025-53770.ps1
# Description: Detect compromise indicators and apply mitigations for CVE-2025-53770 (SharePoint zero-day RCE)

# ────────────────────────────────
#   ASCII BANNER
# ────────────────────────────────
Write-Host @"

  ____________ _____   ____         _____   ____ _____ _   _ _______  
 |___  /  ____|  __ \ / __ \       |  __ \ / __ \_   _| \ | |__   __| 
    / /| |__  | |__) | |  | |______| |__) | |  | || | |  \| |  | |    
   / / |  __| |  _  /| |  | |______|  ___/| |  | || | | . ` |  | |    
  / /__| |____| | \ \| |__| |      | |    | |__| || |_| |\  |  | |    
 /_____|______|_|  \_\\____/       |_|     \____/_____|_| \_|  |_|    
                                                                      
                                                                      
         CVE-2025-53770 Checker - Remote Code Execution (Zero-Day)
                  by @n1chr0x and @BlackRazer67
"@ -ForegroundColor Cyan

Start-Sleep -Seconds 1
Write-Host "`nStarting SharePoint Security Scan..." -ForegroundColor Yellow
Start-Sleep -Seconds 1

# ────────────────────────────────
# 1. Scan for suspicious .aspx files
# ────────────────────────────────
Write-Output "`nScanning for suspicious .aspx files modified in the last 7 days..."
$webShells = Get-ChildItem -Path "C:\inetpub\wwwroot\wss\VirtualDirectories\" -Recurse -Include *.aspx -ErrorAction SilentlyContinue | 
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }

if ($webShells) {
    Write-Output "WARNING: Potential web shells detected:"
    $webShells | Select-Object FullName, LastWriteTime
} else {
    Write-Output "No suspicious .aspx files detected recently."
}

# ────────────────────────────────
# 2. Search ULS logs for deserialization errors
# ────────────────────────────────
Write-Output "`nSearching ULS logs for deserialization or spoofing errors..."
$ulsPath = "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\15\LOGS"
if (Test-Path $ulsPath) {
    Get-ChildItem -Path $ulsPath -Filter *.log |
        Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
        ForEach-Object {
            Select-String -Path $_.FullName -Pattern "deserializ|spoof" -SimpleMatch
        }
} else {
    Write-Output "SharePoint ULS log path not found."
}

# ────────────────────────────────
# 3. Check AMSI status
# ────────────────────────────────
Write-Output "`nChecking AMSI (Antimalware Scan Interface) integration status..."
try {
    $amsi = Get-SPAntivirusScanSettings
    if ($amsi.EnableAmsi) {
        Write-Output "AMSI Integration: ENABLED"
    } else {
        Write-Output "AMSI Integration: DISABLED"
        Write-Output "To enable, run: Set-SPAntivirusScanSettings -EnableAmsi \$true"
    }
} catch {
    Write-Output "Unable to retrieve SharePoint AMSI settings. Are you running with admin SharePoint permissions?"
}

# ────────────────────────────────
# 4. Check Microsoft Defender Antivirus
# ────────────────────────────────
Write-Output "`nChecking Microsoft Defender Antivirus protection status..."
try {
    $defender = Get-MpComputerStatus
    if ($defender.AntivirusEnabled -and $defender.RealTimeProtectionEnabled) {
        Write-Output "Microsoft Defender real-time protection is ENABLED."
    } else {
        Write-Output "Microsoft Defender real-time protection is DISABLED."
        Write-Output "To enable: Set-MpPreference -DisableRealtimeMonitoring \$false"
    }
} catch {
    Write-Output "Unable to check Defender status. Are you on a supported Windows system?"
}

# ────────────────────────────────
# 5. Optional emergency mitigation: Disconnect internet-facing adapters
# ────────────────────────────────
Function Disconnect-Internet {
    Write-Output "Disconnecting all external network interfaces to mitigate potential ongoing attack..."
    Get-NetAdapter | 
        Where-Object {$.Status -eq "Up" -and $.HardwareInterface -eq $true} |
        Disable-NetAdapter -Confirm:$false -Verbose
    Write-Output "External interfaces disabled. Server temporarily isolated."
}

Write-Output "`nIf you're under active attack, run the following command to isolate the server:"
Write-Output "    Disconnect-Internet"

# ────────────────────────────────
# END OF SCRIPT
# ────────────────────────────────