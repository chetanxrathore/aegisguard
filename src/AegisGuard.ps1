<#
.SYNOPSIS
    Comprehensive security assessment including vulnerability analysis, compliance audit, and pen testing simulation.

.DESCRIPTION
    Collects hardware/system/user info, performs security checks, vulnerability checks, and penetration simulation,
    and generates a detailed HTML report.

.VERSION
    2.7 (AegisGuard branding + logo + robust charts + hotfix date parsing fix)

.EXAMPLE
    .\AegisGuard.ps1 -employee-id "emp-123"
#>

#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory = $true)]
    [Alias('employee-id')]
    [ValidateNotNullOrEmpty()]
    [string]$EmployeeId,

    [string]$OutputPath = "",

    [ValidateSet("Basic", "Standard", "Comprehensive")]
    [string]$ScanDepth = "Comprehensive",

    [switch]$IncludePenTest = $true
)

#region Branding
$ToolName = "AegisGuard"
$LogoUrl  = "https://framerusercontent.com/assets/HjTUBJW5vft6vzXlUxCcHnr30g.png"
#endregion

#region Console Encoding Fix (prevents â€¢ issues)
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch { }
#endregion

#region Helper Functions

function Iif {
    param(
        [Parameter(Mandatory=$true)][bool]$Condition,
        [Parameter(Mandatory=$true)]$TrueValue,
        [Parameter(Mandatory=$true)]$FalseValue
    )
    if ($Condition) { return $TrueValue } else { return $FalseValue }
}

function HtmlEncode {
    param([string]$Text)
    if ($null -eq $Text) { return "" }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function SafeJoin {
    param([object[]]$Items, [string]$Sep = ", ")
    if (-not $Items) { return "" }
    return (($Items | Where-Object { $_ -ne $null -and "$_".Trim() -ne "" }) -join $Sep)
}

function Get-ServiceSecurityDescriptorText {
    param([string]$ServiceName)
    try {
        $sd = sc.exe sdshow $ServiceName 2>$null
        if ($LASTEXITCODE -eq 0 -and $sd) { return ($sd | Out-String).Trim() }
    } catch { }
    return ""
}

function TryParse-DateTime {
    param([object]$Value)
    # Returns [datetime] or $null (never throws)
    if ($null -eq $Value) { return $null }
    try {
        if ($Value -is [datetime]) { return $Value }
        $s = "$Value".Trim()
        if ([string]::IsNullOrWhiteSpace($s)) { return $null }
        $dt = $null
        if ([datetime]::TryParse($s, [ref]$dt)) { return $dt }
    } catch { }
    return $null
}

function Get-LastHotfixSafe {
    # Handles systems where InstalledOn is empty / non-date strings
    try {
        $hotfixes = Get-HotFix -ErrorAction SilentlyContinue
        if (-not $hotfixes) { return $null }

        $withParsed = foreach ($hf in $hotfixes) {
            $parsed = TryParse-DateTime $hf.InstalledOn
            [PSCustomObject]@{
                HotFixID      = $hf.HotFixID
                InstalledOn   = $hf.InstalledOn
                ParsedDate    = $parsed
                Description   = $hf.Description
                InstalledBy   = $hf.InstalledBy
                Caption       = $hf.Caption
            }
        }

        # Prefer parsed date; if none parse, fall back to original order
        $candidate = $withParsed | Where-Object { $_.ParsedDate -ne $null } | Sort-Object ParsedDate -Descending | Select-Object -First 1
        if ($candidate) { return $candidate }

        return ($withParsed | Select-Object -First 1)
    } catch {
        return $null
    }
}

function Get-LogoDataUri {
    param([string]$Url)

    # Try to embed as base64 so the report works offline.
    # Fallback: return the URL if download fails.
    try {
        $temp = Join-Path $env:TEMP ("aegisguard_logo_" + [Guid]::NewGuid().ToString("N") + ".png")
        Invoke-WebRequest -Uri $Url -UseBasicParsing -OutFile $temp -TimeoutSec 20 -ErrorAction Stop | Out-Null
        $bytes = [System.IO.File]::ReadAllBytes($temp)
        Remove-Item $temp -Force -ErrorAction SilentlyContinue | Out-Null
        $b64 = [Convert]::ToBase64String($bytes)
        return "data:image/png;base64,$b64"
    } catch {
        return $Url
    }
}

#endregion

#region Global Variables

$EmployeeIdSafe = ($EmployeeId -replace '[\\\/\:\*\?\"\<\>\|]', '_').Trim()
if ([string]::IsNullOrWhiteSpace($EmployeeIdSafe)) { $EmployeeIdSafe = "UNKNOWN" }

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = "$env:USERPROFILE\Desktop\Security_Audit_Report_${EmployeeIdSafe}_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
}

$VulnerabilityScore = 100
$TotalChecks = 0
$PassedChecks = 0
$FailedChecks = 0

#endregion

#region Data Collection

function Get-HardwareInventory {
    $inventory = @()
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($cs) {
            $inventory += [PSCustomObject]@{ Category="Computer System"; Property="Manufacturer"; Value=$cs.Manufacturer }
            $inventory += [PSCustomObject]@{ Category="Computer System"; Property="Model"; Value=$cs.Model }
            $inventory += [PSCustomObject]@{ Category="Computer System"; Property="Total Physical Memory (GB)"; Value=[math]::Round($cs.TotalPhysicalMemory / 1GB, 2) }
        }

        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
        if ($bios) {
            $inventory += [PSCustomObject]@{ Category="BIOS"; Property="SerialNumber"; Value=$bios.SerialNumber }
            $inventory += [PSCustomObject]@{ Category="BIOS"; Property="Version"; Value=$bios.SMBIOSBIOSVersion }
            $inventory += [PSCustomObject]@{ Category="BIOS"; Property="Release Date"; Value=$bios.ReleaseDate }
        }

        $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cpu) {
            $inventory += [PSCustomObject]@{ Category="Processor"; Property="Name"; Value=$cpu.Name }
            $inventory += [PSCustomObject]@{ Category="Processor"; Property="Cores"; Value=$cpu.NumberOfCores }
            $inventory += [PSCustomObject]@{ Category="Processor"; Property="Max Clock Speed (GHz)"; Value=[math]::Round($cpu.MaxClockSpeed / 1000, 2) }
        }

        $disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue
        foreach ($disk in $disks) {
            $encryptionStatus = "Unknown"
            try {
                if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
                    $bitlocker = Get-BitLockerVolume -MountPoint $disk.DeviceID -ErrorAction SilentlyContinue
                    if ($bitlocker) { $encryptionStatus = $bitlocker.ProtectionStatus }
                }
            } catch { }
            $inventory += [PSCustomObject]@{
                Category = "Disk"
                Property = "Drive $($disk.DeviceID)"
                Value    = "Size: $([math]::Round($disk.Size/1GB,2)) GB, Free: $([math]::Round($disk.FreeSpace/1GB,2)) GB, Encryption: $encryptionStatus"
            }
        }

        if (Get-Command Get-NetAdapter -ErrorAction SilentlyContinue) {
            $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } -ErrorAction SilentlyContinue
            foreach ($adapter in $adapters) {
                $ipAddress = (Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
                $dnsServers = (Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
                $inventory += [PSCustomObject]@{
                    Category = "Network"
                    Property = $adapter.Name
                    Value    = "MAC: $($adapter.MacAddress), IP: $(SafeJoin $ipAddress), DNS: $(SafeJoin $dnsServers)"
                }
            }
        }
    } catch { }

    if ($inventory.Count -eq 0) {
        $inventory += [PSCustomObject]@{ Category="Information"; Property="Hardware Inventory"; Value="Could not collect hardware information" }
    }
    return $inventory
}

function Get-SystemInformation {
    $sysInfo = @()
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ($os) {
            $sysInfo += [PSCustomObject]@{ Category="Operating System"; Property="Caption"; Value=$os.Caption }
            $sysInfo += [PSCustomObject]@{ Category="Operating System"; Property="Version"; Value=$os.Version }
            $sysInfo += [PSCustomObject]@{ Category="Operating System"; Property="BuildNumber"; Value=$os.BuildNumber }
            $sysInfo += [PSCustomObject]@{ Category="Operating System"; Property="InstallDate"; Value=$os.InstallDate }
            $sysInfo += [PSCustomObject]@{ Category="Operating System"; Property="LastBootUpTime"; Value=$os.LastBootUpTime }
        }

        $software = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion |
            Sort-Object DisplayName |
            Select-Object -First 20

        $softwareList = $software | ForEach-Object { "$($_.DisplayName) v$($_.DisplayVersion)" }
        $sysInfo += [PSCustomObject]@{ Category="Software"; Property="Installed Applications (sample)"; Value=(SafeJoin $softwareList "; ") }

        try {
            $hotfixes = Get-HotFix -ErrorAction SilentlyContinue | Select-Object HotFixID, InstalledOn
            $hotfixList = @()
            foreach ($hf in $hotfixes) {
                $dateStr = if ($hf.InstalledOn) { "($($hf.InstalledOn))" } else { "(Date unknown)" }
                $hotfixList += "$($hf.HotFixID) $dateStr"
            }
            $sysInfo += [PSCustomObject]@{ Category="Updates"; Property="Recent Hotfixes"; Value=(Iif ($hotfixList.Count -gt 0) (SafeJoin $hotfixList ", ") "None found or access denied") }
        } catch {
            $sysInfo += [PSCustomObject]@{ Category="Updates"; Property="Hotfix Information"; Value="Could not retrieve hotfix information" }
        }

        try {
            $session = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
            $searcher = $session.CreateUpdateSearcher()
            $missingCount = $searcher.Search("IsInstalled=0 and Type='Software'").Updates.Count
            $sysInfo += [PSCustomObject]@{ Category="Updates"; Property="Missing Updates Count"; Value="$missingCount updates pending installation" }
        } catch {
            $sysInfo += [PSCustomObject]@{ Category="Updates"; Property="Missing Updates"; Value="Check not performed (COM object unavailable)" }
        }

        try {
            if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
                $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
                if ($defender) {
                    $avEnabled = $defender.AntivirusEnabled
                    $rtEnabled = $defender.RealTimeProtectionEnabled
                    $sigUpToDate = $false
                    if ($null -ne $defender.PSObject.Properties["AntivirusSignatureUpToDate"]) { $sigUpToDate = $sigUpToDate -or [bool]$defender.AntivirusSignatureUpToDate }
                    if ($null -ne $defender.PSObject.Properties["AntispywareSignatureUpToDate"]) { $sigUpToDate = $sigUpToDate -or [bool]$defender.AntispywareSignatureUpToDate }
                    $sysInfo += [PSCustomObject]@{ Category="Antivirus"; Property="Windows Defender Status"; Value="Enabled: $avEnabled, RealTime: $rtEnabled, SigUpToDate: $sigUpToDate" }
                }
            }
        } catch { }

    } catch { }

    if ($sysInfo.Count -eq 0) {
        $sysInfo += [PSCustomObject]@{ Category="Information"; Property="System Information"; Value="Could not collect system information" }
    }
    return $sysInfo
}

function Get-SimpleUserInformation {
    $userInfo = @()
    try {
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $userInfo += [PSCustomObject]@{ Category="Session"; Property="Current User"; Value=$currentUser }

        if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
            $users = Get-LocalUser -ErrorAction SilentlyContinue
            $enabledUsers = @($users | Where-Object { $_.Enabled -eq $true })
            $disabledUsers = @($users | Where-Object { $_.Enabled -eq $false })
            $userInfo += [PSCustomObject]@{ Category="Local Users"; Property="User Count"; Value="Total: $($users.Count), Enabled: $($enabledUsers.Count), Disabled: $($disabledUsers.Count)" }

            $sampleUsers = $enabledUsers | Select-Object -First 5 | ForEach-Object { $_.Name }
            $userInfo += [PSCustomObject]@{ Category="Local Users"; Property="Sample Enabled Users"; Value=(SafeJoin $sampleUsers ", ") }
        }

        $netAdmins = net localgroup administrators 2>&1
        if ($LASTEXITCODE -eq 0) {
            $adminLines = $netAdmins | Select-Object -Skip 6 | Where-Object { $_ -and $_ -notmatch '^The command' -and $_ -notmatch '^Command' }
            $adminMembers = @()
            foreach ($line in $adminLines) { if ($line.Trim() -ne "") { $adminMembers += $line.Trim() } }
            $userInfo += [PSCustomObject]@{ Category="Privileged Accounts"; Property="Administrators"; Value=(Iif ($adminMembers.Count -gt 0) ("$($adminMembers.Count) members: " + (SafeJoin $adminMembers "; ")) "No members found") }
        }
    } catch {
        $userInfo += [PSCustomObject]@{ Category="Error"; Property="User Information"; Value="Failed to collect user information" }
    }

    if ($userInfo.Count -eq 0) {
        $userInfo += [PSCustomObject]@{ Category="Information"; Property="User Data"; Value="No user information collected" }
    }
    return $userInfo
}

#endregion

#region Core Checks

function Invoke-SecurityChecks {
    $checks = @()
    $script:TotalChecks = 0
    $script:PassedChecks = 0
    $script:FailedChecks = 0

    Write-Host "  Checking Windows Firewall..." -ForegroundColor Gray
    $script:TotalChecks++
    try {
        if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
            $fwProfiles = Get-NetFirewallProfile | Where-Object { $_.Enabled -eq 'True' } -ErrorAction SilentlyContinue
            $fwResult = $fwProfiles.Count -eq 3
            $fwDetails = "Firewall profiles enabled: $($fwProfiles.Count)/3"
        } else {
            $fwDomain  = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"  -Name "EnableFirewall" -ErrorAction SilentlyContinue
            $fwPrivate = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "EnableFirewall" -ErrorAction SilentlyContinue
            $fwPublic  = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"  -Name "EnableFirewall" -ErrorAction SilentlyContinue
            $fwResult = ($fwDomain.EnableFirewall -eq 1) -and ($fwPrivate.EnableFirewall -eq 1) -and ($fwPublic.EnableFirewall -eq 1)
            $fwDetails = "Firewall status via registry policy keys"
        }
    } catch {
        $fwResult = $false
        $fwDetails = "Check failed: $($_.Exception.Message)"
    }
    if ($fwResult) { $script:PassedChecks++ } else { $script:FailedChecks++; $script:VulnerabilityScore -= 5 }

    $checks += [PSCustomObject]@{
        ID="SEC-001"; Check="Windows Firewall Enabled (All Profiles)"
        Result=(Iif $fwResult "PASS" "FAIL")
        Severity="High"; Details=$fwDetails
        ISO27001="A.13.1.1 (Network Security Controls)"
        NISTCSF="PR.AC-5, PR.DS-2"
        Recommendation="Enable all firewall profiles (Domain/Private/Public) and configure inbound/outbound rules appropriately."
    }

    Write-Host "  Checking Remote Desktop Security..." -ForegroundColor Gray
    $script:TotalChecks++
    $rdpKey = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
    $rdpSecurity = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -ErrorAction SilentlyContinue
    $rdpEnabled = $rdpKey -and $rdpKey.fDenyTSConnections -eq 0
    $rdpNLA = $rdpSecurity -and $rdpSecurity.UserAuthentication -eq 1

    if ($rdpEnabled) {
        $rdpResult = $rdpNLA
        $rdpDetails = "RDP Enabled with NLA: $rdpNLA"
        if (-not $rdpNLA) { $script:VulnerabilityScore -= 8 }
    } else {
        $rdpResult = $true
        $rdpDetails = "RDP Disabled"
    }

    if ($rdpResult) { $script:PassedChecks++ } else { $script:FailedChecks++ }

    $checks += [PSCustomObject]@{
        ID="SEC-002"; Check="Remote Desktop Security"
        Result=(Iif $rdpResult "PASS" "FAIL")
        Severity=(Iif $rdpEnabled "High" "Medium")
        Details=$rdpDetails
        ISO27001="A.9.1.2, A.13.1.1"
        NISTCSF="PR.AC-3, PR.AC-7"
        Recommendation="Disable RDP if unused; if needed, enable NLA and restrict access (firewall + allow-list)."
    }

    Write-Host "  Checking Password Policy..." -ForegroundColor Gray
    $script:TotalChecks++
    $secPolicy = @{}
    try {
        secedit /export /cfg "$env:TEMP\secpolicy.cfg" /quiet 2>&1 | Out-Null
        if (Test-Path "$env:TEMP\secpolicy.cfg") {
            $lines = Get-Content "$env:TEMP\secpolicy.cfg"
            foreach ($line in $lines) {
                if ($line -match '^\s*([^=]+)\s*=\s*(.+)$') { $secPolicy[$matches[1].Trim()] = $matches[2].Trim() }
            }
            Remove-Item "$env:TEMP\secpolicy.cfg" -Force -ErrorAction SilentlyContinue
        }
    } catch { }

    $minLength = if ($secPolicy["MinimumPasswordLength"]) { [int]$secPolicy["MinimumPasswordLength"] } else { 0 }
    $complexity = if ($secPolicy["PasswordComplexity"]) { [int]$secPolicy["PasswordComplexity"] } else { 0 }
    $historySize = if ($secPolicy["PasswordHistorySize"]) { [int]$secPolicy["PasswordHistorySize"] } else { 0 }
    $maxAge = if ($secPolicy["MaximumPasswordAge"]) { [int]$secPolicy["MaximumPasswordAge"] } else { 0 }

    $pwdChecks = @(
        @{Name="MinLength>=8"; Ok=($minLength -ge 8)},
        @{Name="Complexity=On"; Ok=($complexity -eq 1)},
        @{Name="History>=5"; Ok=($historySize -ge 5)},
        @{Name="MaxAge<=90"; Ok=($maxAge -le 90 -and $maxAge -gt 0)}
    )
    $passedPwdChecks = ($pwdChecks | Where-Object { $_.Ok }).Count
    $pwdResult = ($passedPwdChecks -eq $pwdChecks.Count)
    $pwdScore = [math]::Round(($passedPwdChecks / $pwdChecks.Count) * 100, 0)
    $script:VulnerabilityScore -= ((4 - $passedPwdChecks) * 3)

    if ($pwdResult) { $script:PassedChecks++ } else { $script:FailedChecks++ }

    $checks += [PSCustomObject]@{
        ID="SEC-003"; Check="Password Policy Strength"
        Result=(Iif $pwdResult "PASS" "PARTIAL")
        Severity="High"
        Details="Score: $pwdScore% (Min: $minLength, Complex: $complexity, History: $historySize, MaxAge: $maxAge days)"
        ISO27001="A.9.4.3, A.9.2.4"
        NISTCSF="PR.AC-1, PR.AC-4"
        Recommendation="Set min 8 chars, complexity on, history >=5, max age <=90 days; enable lockout policy."
    }

    Write-Host "  Checking Audit Logging..." -ForegroundColor Gray
    $script:TotalChecks++
    try {
        $auditPolicy = (auditpol /get /category:* 2>&1 | Out-String)
        $auditChecks = @(
            @{Name="Logon/Logoff"; Pattern="Logon/Logoff.*Success.*Failure"},
            @{Name="Account Management"; Pattern="Account Management.*Success.*Failure"},
            @{Name="Policy Change"; Pattern="Policy Change.*Success.*Failure"},
            @{Name="Privilege Use"; Pattern="Privilege Use.*Success.*Failure"}
        )
        $passedAuditChecks = 0
        foreach ($c in $auditChecks) { if ($auditPolicy -match $c.Pattern) { $passedAuditChecks++ } }
        $auditResult = $passedAuditChecks -ge 3
        $auditDetails = "$passedAuditChecks/4 critical audit categories configured"
        $script:VulnerabilityScore -= ((4 - $passedAuditChecks) * 2)
    } catch {
        $auditResult = $false
        $auditDetails = "Check failed: Could not run auditpol"
        $script:VulnerabilityScore -= 8
    }
    if ($auditResult) { $script:PassedChecks++ } else { $script:FailedChecks++ }

    $checks += [PSCustomObject]@{
        ID="SEC-004"; Check="Audit Logging Configuration"
        Result=(Iif $auditResult "PASS" "FAIL")
        Severity="Medium"; Details=$auditDetails
        ISO27001="A.12.4.1"
        NISTCSF="DE.AE-3, DE.CM-1"
        Recommendation="Enable auditing for Logon/Logoff, Account Mgmt, Policy Change, Privilege Use (Success & Failure)."
    }

    Write-Host "  Checking SMB Security..." -ForegroundColor Gray
    $script:TotalChecks++
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
    $smb1Result = $smb1 -and $smb1.State -eq "Disabled"
    $smbSigning = @()
    try {
        $smbClientSigning = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue).RequireSecuritySignature
        $smbServerSigning = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue).RequireSecuritySignature
        $smbSigning += (Iif ($smbClientSigning -eq 1) "Client: Enabled" "Client: Disabled")
        $smbSigning += (Iif ($smbServerSigning -eq 1) "Server: Enabled" "Server: Disabled")
    } catch { }

    $smbDetails = "SMBv1: $($smb1.State), Signing: $(SafeJoin $smbSigning ', ')"
    if (-not $smb1Result) { $script:VulnerabilityScore -= 10 }
    if ($smbSigning -notcontains "Server: Enabled") { $script:VulnerabilityScore -= 3 }
    if ($smb1Result) { $script:PassedChecks++ } else { $script:FailedChecks++ }

    $checks += [PSCustomObject]@{
        ID="SEC-005"; Check="SMB Protocol Security"
        Result=(Iif $smb1Result "PASS" "FAIL")
        Severity="High"; Details=$smbDetails
        ISO27001="A.13.1.1"
        NISTCSF="PR.AC-5, PR.DS-2"
        Recommendation="Disable SMBv1 and enable SMB signing; restrict SMB exposure (445) using firewall/segmentation."
    }

    Write-Host "  Checking AutoRun Security..." -ForegroundColor Gray
    $script:TotalChecks++
    $autoRun = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
    $autoRunResult = $autoRun -and $autoRun.NoDriveTypeAutoRun -eq 255
    $autoPlay = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutoPlay" -ErrorAction SilentlyContinue
    $autoPlayResult = $autoPlay -and $autoPlay.NoAutoPlay -eq 1
    $autorunFinalResult = $autoRunResult -and $autoPlayResult
    if (-not $autorunFinalResult) { $script:VulnerabilityScore -= 4 }
    if ($autorunFinalResult) { $script:PassedChecks++ } else { $script:FailedChecks++ }

    $checks += [PSCustomObject]@{
        ID="SEC-006"; Check="AutoRun/AutoPlay Security"
        Result=(Iif $autorunFinalResult "PASS" "FAIL")
        Severity="Medium"
        Details="AutoRun: $(Iif $autoRunResult 'Disabled' 'Enabled'), AutoPlay: $(Iif $autoPlayResult 'Disabled' 'Enabled')"
        ISO27001="A.8.2.3"
        NISTCSF="PR.AC-3"
        Recommendation="Disable AutoRun and AutoPlay to prevent execution from removable media."
    }

    Write-Host "  Checking Network Shares..." -ForegroundColor Gray
    $script:TotalChecks++
    $shares = @()
    $shareResult = $true
    $shareDetails = ""
    if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) {
        $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike "*$" -and $_.Name -ne "IPC$" }
        $shareResult = $shares.Count -eq 0
        $shareDetails = "Found $($shares.Count) shares: $(SafeJoin ($shares.Name) ', ')"
    } else {
        $sharesOutput = net share 2>&1
        $shares = $sharesOutput | Where-Object { $_ -match '^[A-Z]' -and $_ -notmatch '^The command' } | ForEach-Object { ($_ -split '\s+')[0] }
        $shareResult = $shares.Count -eq 0
        $shareDetails = "Found $($shares.Count) shares (via net share)"
    }

    $nullSession = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RestrictNullSessAccess" -ErrorAction SilentlyContinue
    $nullSessionResult = $nullSession -and $nullSession.RestrictNullSessAccess -eq 1
    $networkFinalResult = $shareResult -and $nullSessionResult
    if (-not $shareResult) { $script:VulnerabilityScore -= 5 }
    if (-not $nullSessionResult) { $script:VulnerabilityScore -= 3 }
    if ($networkFinalResult) { $script:PassedChecks++ } else { $script:FailedChecks++ }

    $checks += [PSCustomObject]@{
        ID="SEC-007"; Check="Network Sharing Security"
        Result=(Iif $networkFinalResult "PASS" "FAIL")
        Severity="Medium"
        Details="$shareDetails, Null Sessions: $(Iif $nullSessionResult 'Restricted' 'Allowed')"
        ISO27001="A.13.1.1"
        NISTCSF="PR.AC-5"
        Recommendation="Review share ACLs; remove unnecessary shares; restrict null sessions; enable access auditing."
    }

    Write-Host "  Checking Windows Update..." -ForegroundColor Gray
    $script:TotalChecks++
    $wuService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
    $wuResult = $wuService -and $wuService.Status -eq "Running"

    # FIX: avoid Sort-Object InstalledOn parse exceptions
    $lastUpdate = Get-LastHotfixSafe
    $lastUpdateDt = if ($lastUpdate) { TryParse-DateTime $lastUpdate.ParsedDate } else { $null }
    $updateAge = if ($lastUpdateDt) { (New-TimeSpan -Start $lastUpdateDt -End (Get-Date)).Days } else { 999 }
    $updateRecent = $updateAge -lt 30

    $updateFinalResult = $wuResult -and $updateRecent
    if (-not $wuResult) { $script:VulnerabilityScore -= 5 }
    if (-not $updateRecent) { $script:VulnerabilityScore -= 3 }
    if ($updateFinalResult) { $script:PassedChecks++ } else { $script:FailedChecks++ }

    $lastHotfixShown = if ($lastUpdate -and $lastUpdate.HotFixID) { $lastUpdate.HotFixID } else { "Unknown" }
    $htmlLastDate = if ($lastUpdateDt) { $lastUpdateDt.ToString("yyyy-MM-dd") } else { "Unknown" }

    $checks += [PSCustomObject]@{
        ID="SEC-008"; Check="Update Management"
        Result=(Iif $updateFinalResult "PASS" "FAIL")
        Severity="High"
        Details="Service: $($wuService.Status), Last hotfix: $lastHotfixShown, Last update date: $htmlLastDate, Age: $updateAge days"
        ISO27001="A.12.6.1"
        NISTCSF="PR.IP-12"
        Recommendation="Keep Windows Update running; patch within 30 days (preferably sooner for critical patches)."
    }

    Write-Host "  Checking Unnecessary Services..." -ForegroundColor Gray
    $script:TotalChecks++
    $dangerousServices = @(
        @{Name="Telnet"; Display="Telnet Server"},
        @{Name="ftpsvc"; Display="FTP Server"},
        @{Name="SNMP"; Display="SNMP Service"},
        @{Name="RemoteRegistry"; Display="Remote Registry"},
        @{Name="W3SVC"; Display="IIS Web Server"}
    )
    $runningServices = @()
    foreach ($service in $dangerousServices) {
        $svc = Get-Service -Name $service.Name -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") { $runningServices += $service.Display }
    }
    $serviceResult = $runningServices.Count -eq 0
    if (-not $serviceResult) { $script:VulnerabilityScore -= ($runningServices.Count * 3) }
    if ($serviceResult) { $script:PassedChecks++ } else { $script:FailedChecks++ }

    $checks += [PSCustomObject]@{
        ID="SEC-009"; Check="Unnecessary Services"
        Result=(Iif $serviceResult "PASS" "FAIL")
        Severity="High"
        Details=(Iif ($runningServices.Count -gt 0) ("Running: " + (SafeJoin $runningServices ", ")) "No dangerous services running")
        ISO27001="A.12.5.1"
        NISTCSF="PR.IP-1"
        Recommendation="Disable Telnet/FTP/SNMP/RemoteRegistry/IIS if not required."
    }

    Write-Host "  Checking PowerShell Security..." -ForegroundColor Gray
    $script:TotalChecks++
    $psLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
    $psTranscription = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -ErrorAction SilentlyContinue
    $psExecutionPolicy = Get-ExecutionPolicy -Scope LocalMachine

    $psLoggingEnabled = $psLogging -and $psLogging.EnableScriptBlockLogging -eq 1
    $psTranscriptionEnabled = $psTranscription -and $psTranscription.EnableTranscripting -eq 1
    $psRestricted = $psExecutionPolicy -in @("Restricted", "AllSigned", "RemoteSigned")

    if (-not $psRestricted) { $script:VulnerabilityScore -= 4 }
    if (-not $psLoggingEnabled) { $script:VulnerabilityScore -= 2 }

    $psResult = $psRestricted
    if ($psResult) { $script:PassedChecks++ } else { $script:FailedChecks++ }

    $checks += [PSCustomObject]@{
        ID="SEC-010"; Check="PowerShell Security"
        Result=(Iif $psResult "PASS" "FAIL")
        Severity="Medium"
        Details="Logging: $psLoggingEnabled, Transcription: $psTranscriptionEnabled, Execution Policy: $psExecutionPolicy"
        ISO27001="A.12.4.1"
        NISTCSF="DE.CM-1"
        Recommendation="Use RemoteSigned/AllSigned; enable ScriptBlock logging and Transcription."
    }

    if ($ScanDepth -in @("Standard", "Comprehensive")) {

        Write-Host "  Checking User Account Control..." -ForegroundColor Gray
        $script:TotalChecks++
        $uac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
        $uacResult = $uac -and $uac.EnableLUA -eq 1
        if (-not $uacResult) { $script:VulnerabilityScore -= 7 }
        if ($uacResult) { $script:PassedChecks++ } else { $script:FailedChecks++ }

        $checks += [PSCustomObject]@{
            ID="SEC-011"; Check="User Account Control (UAC)"
            Result=(Iif $uacResult "PASS" "FAIL")
            Severity="High"
            Details="UAC Enabled: $uacResult"
            ISO27001="A.9.2.3"
            NISTCSF="PR.AC-6"
            Recommendation="Enable UAC and avoid routine admin usage."
        }

        Write-Host "  Checking BitLocker Encryption..." -ForegroundColor Gray
        $script:TotalChecks++
        $bitlockerStatus = "Not Available"
        $bitlockerResult = $false
        try {
            if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
                $bitlocker = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
                if ($bitlocker) {
                    $bitlockerStatus = $bitlocker.VolumeStatus
                    $bitlockerResult = $bitlocker.VolumeStatus -eq "FullyEncrypted"
                }
            }
        } catch { }
        if (-not $bitlockerResult) { $script:VulnerabilityScore -= 8 }
        if ($bitlockerResult) { $script:PassedChecks++ } else { $script:FailedChecks++ }

        $checks += [PSCustomObject]@{
            ID="SEC-012"; Check="Disk Encryption (BitLocker)"
            Result=(Iif $bitlockerResult "PASS" "FAIL")
            Severity="High"
            Details="Status: $bitlockerStatus"
            ISO27001="A.10.1.1"
            NISTCSF="PR.DS-1"
            Recommendation="Enable BitLocker and store recovery keys securely."
        }

        Write-Host "  Checking Antivirus Protection..." -ForegroundColor Gray
        $script:TotalChecks++
        $avStatus = "Unknown"
        $avResult = $false
        try {
            if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
                $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
                if ($defender) {
                    $avEnabled = [bool]$defender.AntivirusEnabled
                    $rtEnabled = [bool]$defender.RealTimeProtectionEnabled

                    $sigUpToDate = $false
                    if ($null -ne $defender.PSObject.Properties["AntivirusSignatureUpToDate"]) { $sigUpToDate = $sigUpToDate -or [bool]$defender.AntivirusSignatureUpToDate }
                    if ($null -ne $defender.PSObject.Properties["AntispywareSignatureUpToDate"]) { $sigUpToDate = $sigUpToDate -or [bool]$defender.AntispywareSignatureUpToDate }

                    $lastUpdated = $null
                    if ($null -ne $defender.PSObject.Properties["AntivirusSignatureLastUpdated"]) { $lastUpdated = $defender.AntivirusSignatureLastUpdated }
                    if (-not $lastUpdated -and $null -ne $defender.PSObject.Properties["AntispywareSignatureLastUpdated"]) { $lastUpdated = $defender.AntispywareSignatureLastUpdated }

                    $ageDays = $null
                    $ageOk = $false
                    if ($lastUpdated) {
                        $lastDt = TryParse-DateTime $lastUpdated
                        if ($lastDt) {
                            $ageDays = (New-TimeSpan -Start $lastDt -End (Get-Date)).Days
                            $ageOk = $ageDays -le 7
                        }
                    }

                    $avResult = $avEnabled -and $rtEnabled -and ($sigUpToDate -or $ageOk)
                    $avStatus = "Windows Defender - Enabled: $avEnabled, RealTime: $rtEnabled, SigUpToDate: $sigUpToDate, SigLastUpdated: $lastUpdated, SigAgeDays: $ageDays"
                }
            } else {
                $wmiAV = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
                if ($wmiAV) {
                    $first = $wmiAV | Select-Object -First 1
                    $avStatus = "$($first.displayName) - ProductState: $($first.productState) (SecurityCenter2)"
                    $avResult = $true
                } else {
                    $avStatus = "No antivirus detected via SecurityCenter2"
                    $avResult = $false
                }
            }
        } catch {
            $avStatus = "AV check failed: $($_.Exception.Message)"
            $avResult = $false
        }

        if (-not $avResult) { $script:VulnerabilityScore -= 10 }
        if ($avResult) { $script:PassedChecks++ } else { $script:FailedChecks++ }

        $checks += [PSCustomObject]@{
            ID="SEC-013"; Check="Antivirus Protection"
            Result=(Iif $avResult "PASS" "FAIL")
            Severity="High"
            Details=$avStatus
            ISO27001="A.12.2.1"
            NISTCSF="DE.CM-4"
            Recommendation="Ensure AV enabled + real-time on + signatures up-to-date (or updated within 7 days)."
        }

        Write-Host "  Checking Screen Saver Lock..." -ForegroundColor Gray
        $script:TotalChecks++
        $screenSaver = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -ErrorAction SilentlyContinue
        $screenSaverTimeout = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue
        $screenSaverSecureSetting = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue

        $screenSaverEnabled = $screenSaver -and $screenSaver.ScreenSaveActive -eq "1"
        $screenSaverTime = if ($screenSaverTimeout) { [int]$screenSaverTimeout.ScreenSaveTimeOut } else { 0 }
        $screenSaverSecure = $screenSaverTime -gt 0 -and $screenSaverTime -le 900
        $requiresPassword = $screenSaverSecureSetting -and $screenSaverSecureSetting.ScreenSaverIsSecure -eq "1"

        $screenResult = $screenSaverEnabled -and $screenSaverSecure -and $requiresPassword
        if (-not $screenResult) { $script:VulnerabilityScore -= 3 }
        if ($screenResult) { $script:PassedChecks++ } else { $script:FailedChecks++ }

        $checks += [PSCustomObject]@{
            ID="SEC-014"; Check="Screen Saver Lock"
            Result=(Iif $screenResult "PASS" "FAIL")
            Severity="Medium"
            Details="Enabled: $screenSaverEnabled, Timeout: $screenSaverTime seconds, Password: $requiresPassword"
            ISO27001="A.11.2.8"
            NISTCSF="PR.AC-1"
            Recommendation="Enable screen lock with password and timeout <= 15 minutes."
        }
    }

    if ($ScanDepth -eq "Comprehensive") {

        Write-Host "  Checking Event Log Configuration..." -ForegroundColor Gray
        $script:TotalChecks++
        $eventLogs = @("Application","Security","System")
        $passedLogs = 0
        foreach ($log in $eventLogs) {
            try {
                $logConfig = Get-EventLog -LogName $log -ErrorAction SilentlyContinue
                if ($logConfig -and $logConfig.MaximumKilobytes -ge 20480) { $passedLogs++ }
            } catch { }
        }
        $logResult = $passedLogs -eq 3
        if (-not $logResult) { $script:VulnerabilityScore -= 2 }
        if ($logResult) { $script:PassedChecks++ } else { $script:FailedChecks++ }

        $checks += [PSCustomObject]@{
            ID="SEC-015"; Check="Event Log Configuration"
            Result=(Iif $logResult "PASS" "FAIL")
            Severity="Low"
            Details="$passedLogs/3 logs configured with adequate size (>=20MB)"
            ISO27001="A.12.4.1"
            NISTCSF="DE.AE-3"
            Recommendation="Increase event log sizes and centralize log retention."
        }

        Write-Host "  Checking Network Protocol Security..." -ForegroundColor Gray
        $script:TotalChecks++
        $llmnr = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
        $llmnrDisabled = $llmnr -and $llmnr.EnableMulticast -eq 0

        $netbiosDisabled = $true
        if (Get-Command Get-NetAdapter -ErrorAction SilentlyContinue) {
            $adapters = Get-NetAdapter -ErrorAction SilentlyContinue
            foreach ($adapter in $adapters) {
                $netbios = Get-NetAdapterBinding -Name $adapter.Name -ComponentID "ms_netbt" -ErrorAction SilentlyContinue
                if ($netbios -and $netbios.Enabled) { $netbiosDisabled = $false; break }
            }
        }

        $protocolResult = $llmnrDisabled -and $netbiosDisabled
        if (-not $protocolResult) { $script:VulnerabilityScore -= 3 }
        if ($protocolResult) { $script:PassedChecks++ } else { $script:FailedChecks++ }

        $checks += [PSCustomObject]@{
            ID="SEC-016"; Check="Network Protocol Security"
            Result=(Iif $protocolResult "PASS" "FAIL")
            Severity="Medium"
            Details="LLMNR: $(Iif $llmnrDisabled 'Disabled' 'Enabled'), NetBIOS: $(Iif $netbiosDisabled 'Disabled' 'Enabled')"
            ISO27001="A.13.1.1"
            NISTCSF="PR.AC-5"
            Recommendation="Disable LLMNR and NetBIOS over TCP/IP unless strictly required."
        }

        Write-Host "  Checking Windows Features Security..." -ForegroundColor Gray
        $script:TotalChecks++
        $dangerousFeatures = @(
            @{Name="MicrosoftWindowsPowerShellV2"; Display="PowerShell 2.0"},
            @{Name="Internet-Explorer-Optional-amd64"; Display="Internet Explorer"},
            @{Name="Printing-XPSServices-Features"; Display="XPS Services"}
        )
        $enabledFeatures = @()
        foreach ($feature in $dangerousFeatures) {
            $feat = Get-WindowsOptionalFeature -Online -FeatureName $feature.Name -ErrorAction SilentlyContinue
            if ($feat -and $feat.State -eq "Enabled") { $enabledFeatures += $feature.Display }
        }
        $featureResult = $enabledFeatures.Count -eq 0
        if (-not $featureResult) { $script:VulnerabilityScore -= ($enabledFeatures.Count * 2) }
        if ($featureResult) { $script:PassedChecks++ } else { $script:FailedChecks++ }

        $checks += [PSCustomObject]@{
            ID="SEC-017"; Check="Windows Features Security"
            Result=(Iif $featureResult "PASS" "FAIL")
            Severity="Medium"
            Details=(Iif ($enabledFeatures.Count -gt 0) ("Enabled: " + (SafeJoin $enabledFeatures ", ")) "No dangerous features enabled")
            ISO27001="A.12.5.1"
            NISTCSF="PR.PT-3"
            Recommendation="Disable PowerShell 2.0, IE optional components, and XPS services unless needed."
        }
    }

    if ($script:VulnerabilityScore -lt 0) { $script:VulnerabilityScore = 0 }
    if ($script:VulnerabilityScore -gt 100) { $script:VulnerabilityScore = 100 }

    return $checks
}

function Invoke-VulnerabilityAssessment {
    $vulnerabilities = @()

    Write-Host "  Checking software versions..." -ForegroundColor Gray
    try {
        $javaPath = Get-ItemProperty "HKLM:\SOFTWARE\JavaSoft\Java Runtime Environment" -Name "CurrentVersion" -ErrorAction SilentlyContinue
        if ($javaPath) {
            $javaVersion = $javaPath.CurrentVersion
            if ($javaVersion -lt "1.8") {
                $vulnerabilities += [PSCustomObject]@{ Software="Java Runtime"; Version=$javaVersion; Risk="High"; CVE="Multiple CVEs"; Recommendation="Update Java to version 8 or later" }
                $script:VulnerabilityScore -= 7
            }
        }
    } catch { }

    Write-Host "  Checking open ports..." -ForegroundColor Gray
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        $listeningPorts = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Select-Object LocalPort, OwningProcess | Sort-Object LocalPort -Unique

        $dangerousPorts = @{
            21="FTP (Plaintext credentials)";
            23="Telnet (Plaintext credentials)";
            80="HTTP (Unencrypted web traffic)";
            135="RPC/DCOM";
            139="NetBIOS";
            445="SMB";
            3389="RDP"
        }

        foreach ($port in $listeningPorts) {
            if ($dangerousPorts.ContainsKey($port.LocalPort)) {
                $process = Get-Process -Id $port.OwningProcess -ErrorAction SilentlyContinue
                $processName = if ($process) { $process.ProcessName } else { "Unknown" }
                $risk = if ($port.LocalPort -in @(21,23,3389)) { "High" } else { "Medium" }

                $vulnerabilities += [PSCustomObject]@{
                    Port=$port.LocalPort
                    Service=$dangerousPorts[$port.LocalPort]
                    Process=$processName
                    Risk=$risk
                    Recommendation="Close port or restrict access via firewall"
                }

                $script:VulnerabilityScore -= (Iif ($risk -eq "High") 5 3)
            }
        }
    }

    Write-Host "  Checking file permissions..." -ForegroundColor Gray
    $sensitiveFiles = @(
        "$env:WINDIR\System32\cmd.exe",
        "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe",
        "$env:WINDIR\System32\wscript.exe",
        "$env:WINDIR\System32\cscript.exe"
    )
    foreach ($file in $sensitiveFiles) {
        if (Test-Path $file) {
            try {
                $acl = Get-Acl -Path $file -ErrorAction SilentlyContinue
                if ($acl) {
                    $weakAce = $acl.Access | Where-Object {
                        ($_.IdentityReference -like "*Everyone*" -or $_.IdentityReference -like "*Users*" -or $_.IdentityReference -like "*Authenticated Users*") -and
                        ($_.FileSystemRights -match "Write|FullControl|ChangePermissions|TakeOwnership")
                    }
                    if ($weakAce) {
                        $first = $weakAce | Select-Object -First 1
                        $vulnerabilities += [PSCustomObject]@{
                            File=$file
                            Permission=$first.FileSystemRights
                            Identity=$first.IdentityReference
                            Risk="Critical"
                            Recommendation="Restrict permissions to TrustedInstaller and SYSTEM"
                        }
                        $script:VulnerabilityScore -= 8
                    }
                }
            } catch { }
        }
    }

    Write-Host "  Checking .NET Framework version..." -ForegroundColor Gray
    try {
        $netVersions = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP" -Recurse -ErrorAction SilentlyContinue |
            Get-ItemProperty -Name Version -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -match '^(?!S)\p{L}' } |
            Select-Object Version
        if ($netVersions) {
            $latestNet = $netVersions | Sort-Object Version -Descending | Select-Object -First 1
            $netVersion = [version]$latestNet.Version
            if ($netVersion.Major -lt 4) {
                $vulnerabilities += [PSCustomObject]@{ Software=".NET Framework"; Version=$netVersion.ToString(); Risk="High"; CVE="Multiple CVEs"; Recommendation="Update to .NET Framework 4.8 or later" }
                $script:VulnerabilityScore -= 7
            }
        }
    } catch { }

    if ($script:VulnerabilityScore -lt 0) { $script:VulnerabilityScore = 0 }
    return $vulnerabilities
}

function Invoke-PenetrationTesting {
    $penTestResults = @()
    if (-not $IncludePenTest) { return $penTestResults }

    Write-Host "  Simulating password attacks..." -ForegroundColor Gray
    $penTestResults += [PSCustomObject]@{
        Test="Password Strength Simulation"
        Result="Weak passwords potentially in use"
        Severity="High"
        Details="Simulation only (no cracking performed). Common patterns like Password123, admin123, username+year may exist."
        Recommendation="Enforce strong password policy + lockout; enable MFA where possible."
    }
    $script:VulnerabilityScore -= 8

    Write-Host "  Simulating service enumeration..." -ForegroundColor Gray
    try {
        $vulnerableServices = Get-Service -ErrorAction SilentlyContinue |
            Where-Object { $_.StartType -eq "Automatic" -and $_.Status -eq "Running" -and $_.Name -in @("RemoteRegistry","SNMP","W3SVC","FTPSVC") }

        if ($vulnerableServices.Count -gt 0) {
            $penTestResults += [PSCustomObject]@{
                Test="Service Enumeration"
                Result="Potentially vulnerable services found"
                Severity="Medium"
                Details="Found services: $(SafeJoin ($vulnerableServices.Name) ', ')"
                Recommendation="Disable unnecessary services; restrict exposure; review service account privileges."
            }
            $script:VulnerabilityScore -= 5
        }
    } catch { }

    Write-Host "  Simulating network share attacks..." -ForegroundColor Gray
    try {
        if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) {
            $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike "*$" -and $_.Name -ne "IPC$" }
            if ($shares.Count -gt 0) {
                $penTestResults += [PSCustomObject]@{
                    Test="Network Share Enumeration"
                    Result="Network shares accessible"
                    Severity="Medium"
                    Details="Found $($shares.Count) shares: $(SafeJoin ($shares.Name) ', ')"
                    Recommendation="Review share permissions; remove unnecessary shares; enable access auditing."
                }
                $script:VulnerabilityScore -= 5
            }
        }
    } catch { }

    Write-Host "  Simulating privilege escalation..." -ForegroundColor Gray
    try {
        $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
            Where-Object { $_.StartMode -eq "Auto" -and $_.State -eq "Running" }

        $suspicious = @()
        foreach ($svc in $services) {
            $runAs = "$($svc.StartName)".ToLower()
            $isHighPriv = ($runAs -like "*localsystem*") -or ($runAs -like "*local system*") -or ($runAs -like "*system*")
            $isCustom = (-not ($runAs -like "*localservice*") -and -not ($runAs -like "*networkservice*") -and -not ($runAs -like "*localsystem*") -and -not ($runAs -like "*system*"))
            if ($isHighPriv -or $isCustom) { $suspicious += $svc }
        }

        if ($suspicious.Count -gt 0) {
            # NO LIMIT. Include all findings.
            $detailLines = New-Object System.Collections.Generic.List[string]
            foreach ($s in $suspicious) {
                $sdText = Get-ServiceSecurityDescriptorText -ServiceName $s.Name
                $sdShort = if ($sdText.Length -gt 600) { $sdText.Substring(0,600) + "..." } else { $sdText }

                $detailLines.Add(@"
Name: $($s.Name)
DisplayName: $($s.DisplayName)
RunAs: $($s.StartName)
State/StartMode: $($s.State)/$($s.StartMode)
PID: $($s.ProcessId)
Path: $($s.PathName)
ServiceSDDL(sample): $sdShort
"@.Trim())
            }

            $penTestResults += [PSCustomObject]@{
                Test="Privilege Escalation / Weak Service Permissions (Simulation)"
                Result="Services running with higher privilege or custom accounts detected"
                Severity="High"
                Details="Suspicious auto-running services detected: $($suspicious.Count)`n`n" + ($detailLines -join "`n`n---`n`n")
                Recommendation="For each service: review service DACL (sc sdshow), binary path ACLs (icacls), quote paths with spaces, and avoid LocalSystem where not required."
            }
            $script:VulnerabilityScore -= 8
        }
    } catch { }

    if ($script:VulnerabilityScore -lt 0) { $script:VulnerabilityScore = 0 }
    return $penTestResults
}

#endregion

#region Report Generation

function New-SecurityReport {
    param(
        [array]$Hardware,
        [array]$System,
        [array]$Users,
        [array]$SecurityChecks,
        [array]$Vulnerabilities,
        [array]$PenTestResults,
        [string]$EmployeeId
    )

    $complianceScore = if ($TotalChecks -gt 0) { [math]::Round(($PassedChecks / $TotalChecks) * 100, 0) } else { 0 }
    $securityScore = $VulnerabilityScore

    $securityRating = if ($securityScore -ge 90) { "Excellent" }
        elseif ($securityScore -ge 75) { "Good" }
        elseif ($securityScore -ge 60) { "Fair" }
        elseif ($securityScore -ge 40) { "Poor" }
        else { "Critical" }

    $reportTitle = "$ToolName - Comprehensive Security Audit Report - Employee ID: $EmployeeId"
    $logoSrc = Get-LogoDataUri -Url $LogoUrl

    function New-DonutSvg {
        param([int]$Percent, [string]$Label)
        $p = [math]::Max([math]::Min($Percent, 100), 0)
        $r = 52
        $c = [math]::Round((2 * [math]::PI * $r), 2)
        $dash = [math]::Round(($c * $p / 100.0), 2)
        $gap  = [math]::Round(($c - $dash), 2)

        return @"
<div class="donutWrap">
  <svg class="donutSvg" viewBox="0 0 120 120" aria-label="$(HtmlEncode $Label)">
    <circle class="donutTrack" cx="60" cy="60" r="$r"></circle>
    <circle class="donutArc" cx="60" cy="60" r="$r" style="stroke-dasharray:${dash} ${gap};"></circle>
    <text x="60" y="64" text-anchor="middle" class="donutText">$p%</text>
  </svg>
  <div class="donutSub">$(HtmlEncode $Label)</div>
</div>
"@
    }

    $securityDonut  = New-DonutSvg -Percent $securityScore  -Label "Security Score"
    $complianceDonut = New-DonutSvg -Percent $complianceScore -Label "Compliance"

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>$(HtmlEncode $reportTitle)</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Segoe UI, Arial; margin: 20px; background: #f5f7fa; color: #333; }
        .container { max-width: 1400px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 10px; box-shadow: 0 2px 20px rgba(0,0,0,0.1); }
        .topbar { display:flex; align-items:flex-start; justify-content:space-between; gap: 16px; }
        .brand { display:flex; flex-direction:column; gap: 6px; }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; margin: 0 0 6px 0; }
        .logo { max-height: 56px; max-width: 240px; object-fit: contain; }
        .toolTag { font-size: 12px; color:#6b7280; font-weight: 700; letter-spacing: .3px; }
        h2 { color: #34495e; border-bottom: 2px solid #bdc3c7; padding-bottom: 5px; margin-top: 30px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 25px; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; vertical-align: top; }
        th { background: #3498db; color: #fff; }
        tr:nth-child(even) { background: #f8f9fa; }
        .PASS { color: #27ae60; font-weight: bold; }
        .FAIL { color: #e74c3c; font-weight: bold; }
        .PARTIAL { color: #f39c12; font-weight: bold; }
        .badge { display: inline-block; padding: 2px 10px; border-radius: 14px; font-size: 12px; font-weight: 700; }
        .badge-high { background: #ffebee; color: #c62828; }
        .badge-medium { background: #fff3e0; color: #ef6c00; }
        .badge-low { background: #e8f5e8; color: #2e7d32; }
        .summary { background: #667eea; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff; padding: 18px; border-radius: 10px; margin: 15px 0 25px 0; }
        .timestamp { color: #7f8c8d; font-size: 12px; text-align: right; margin-bottom: 14px; }
        .summary-grid { display: grid; grid-template-columns: 1fr 360px; gap: 16px; align-items: center; }
        .charts { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; justify-items: center; }
        .donutWrap { display:flex; flex-direction:column; align-items:center; gap: 6px; }
        .donutSvg { width: 150px; height: 150px; }
        .donutTrack { fill:none; stroke: rgba(255,255,255,0.25); stroke-width: 12; }
        .donutArc { fill:none; stroke: rgba(46,204,113,0.95); stroke-width: 12; stroke-linecap: round; transform: rotate(-90deg); transform-origin: 60px 60px; }
        .donutText { font-size: 20px; font-weight: 800; fill: #fff; }
        .donutSub { font-size: 12px; opacity: 0.95; text-align: center; }
        .donutWrap:nth-child(2) .donutArc { stroke: rgba(52,152,219,0.95); }
        details { background: #f8f9fa; border: 1px solid #e0e0e0; padding: 10px; border-radius: 8px; }
        details summary { cursor: pointer; font-weight: 700; }
        pre { white-space: pre-wrap; word-break: break-word; margin: 8px 0 0 0; }
    </style>
</head>
<body>
<div class="container">

    <div class="topbar">
        <div class="brand">
            <div class="toolTag">$ToolName</div>
            <h1>$(HtmlEncode $reportTitle)</h1>
        </div>
        <img class="logo" src="$(HtmlEncode $logoSrc)" alt="Sysmorph Logo">
    </div>

    <div class="timestamp">Generated on: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Computer: $(HtmlEncode $env:COMPUTERNAME)</div>

    <div class="summary">
        <h2 style="color:#fff;border-bottom:none;margin-top:0;">Executive Summary</h2>
        <div class="summary-grid">
            <div>
                <p><strong>Employee ID:</strong> $(HtmlEncode $EmployeeId) | <strong>Scan Depth:</strong> $(HtmlEncode $ScanDepth) | <strong>Pen Test Simulation:</strong> $($IncludePenTest.ToString().ToUpper())</p>
                <p><strong>Security Score:</strong> $securityScore/100 ($securityRating) | <strong>Compliance:</strong> $PassedChecks/$TotalChecks checks passed ($complianceScore%)</p>
            </div>
            <div class="charts">
                $securityDonut
                $complianceDonut
            </div>
        </div>
    </div>
"@

    $html += "<h2>Hardware Inventory</h2><table><tr><th>Category</th><th>Property</th><th>Value</th></tr>"
    foreach ($item in $Hardware) {
        $html += "<tr><td>$(HtmlEncode $item.Category)</td><td>$(HtmlEncode $item.Property)</td><td>$(HtmlEncode $item.Value)</td></tr>"
    }
    $html += "</table>"

    $html += "<h2>System Information</h2><table><tr><th>Category</th><th>Property</th><th>Value</th></tr>"
    foreach ($item in $System) {
        $html += "<tr><td>$(HtmlEncode $item.Category)</td><td>$(HtmlEncode $item.Property)</td><td>$(HtmlEncode $item.Value)</td></tr>"
    }
    $html += "</table>"

    $html += "<h2>User & Security Context</h2><table><tr><th>Category</th><th>Property</th><th>Value</th></tr>"
    foreach ($item in $Users) {
        $html += "<tr><td>$(HtmlEncode $item.Category)</td><td>$(HtmlEncode $item.Property)</td><td>$(HtmlEncode $item.Value)</td></tr>"
    }
    $html += "</table>"

    $html += "<h2>Security & Compliance Checks</h2><table><tr><th>ID</th><th>Check</th><th>Result</th><th>Severity</th><th>Details</th><th>ISO 27001</th><th>NIST CSF</th><th>Recommendation</th></tr>"
    foreach ($check in $SecurityChecks) {
        $sev = ($check.Severity).ToLower()
        $badge = "badge-$sev"
        $details = (HtmlEncode ($check.Details)) -replace "`r?`n","<br>"
        $html += "<tr>"
        $html += "<td>$(HtmlEncode $check.ID)</td>"
        $html += "<td>$(HtmlEncode $check.Check)</td>"
        $html += "<td class='$($check.Result)'>$(HtmlEncode $check.Result)</td>"
        $html += "<td><span class='badge $badge'>$(HtmlEncode $check.Severity)</span></td>"
        $html += "<td>$details</td>"
        $html += "<td>$(HtmlEncode $check.ISO27001)</td>"
        $html += "<td>$(HtmlEncode $check.NISTCSF)</td>"
        $html += "<td>$(HtmlEncode $check.Recommendation)</td>"
        $html += "</tr>"
    }
    $html += "</table>"

    if ($Vulnerabilities -and $Vulnerabilities.Count -gt 0) {
        $html += "<h2>Vulnerability Assessment Results</h2><table><tr><th>Component</th><th>Details</th><th>Risk</th><th>CVE/Type</th><th>Recommendation</th></tr>"
        foreach ($v in $Vulnerabilities) {
            $component = if ($v.Software) { $v.Software } elseif ($v.Port) { "Port $($v.Port)" } elseif ($v.File) { "File $($v.File)" } else { "Unknown" }
            $details = if ($v.Version) { $v.Version } elseif ($v.Service) { "$($v.Service) / $($v.Process)" } elseif ($v.Permission) { "$($v.Permission) - $($v.Identity)" } else { $v.Details }
            $cve = if ($v.CVE) { $v.CVE } else { "Configuration" }
            $html += "<tr><td>$(HtmlEncode $component)</td><td>$(HtmlEncode $details)</td><td>$(HtmlEncode $v.Risk)</td><td>$(HtmlEncode $cve)</td><td>$(HtmlEncode $v.Recommendation)</td></tr>"
        }
        $html += "</table>"
    }

    if ($IncludePenTest -and $PenTestResults -and $PenTestResults.Count -gt 0) {
        $html += "<h2>Penetration Testing Simulation Results</h2><table><tr><th>Scenario</th><th>Result</th><th>Severity</th><th>Details</th><th>Recommendation</th></tr>"
        foreach ($t in $PenTestResults) {

            $rawDetails = "$($t.Details)"
            $detailsHtml = ""
            if ($t.Test -like "Privilege Escalation / Weak Service Permissions*") {
                $detailsHtml = "<details><summary>View full details</summary><pre>$(HtmlEncode $rawDetails)</pre></details>"
            } else {
                $detailsHtml = ((HtmlEncode $rawDetails) -replace "`r?`n","<br>")
            }

            $html += "<tr><td>$(HtmlEncode $t.Test)</td><td>$(HtmlEncode $t.Result)</td><td>$(HtmlEncode $t.Severity)</td><td>$detailsHtml</td><td>$(HtmlEncode $t.Recommendation)</td></tr>"
        }
        $html += "</table>"
    }

    $html += @"
    <div class="timestamp">
        Report generated by $ToolName (Security Audit Script v2.7)<br>
        Confidential. Contains sensitive security information.
    </div>
</div>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8
}

#endregion

#region Main

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "                 $ToolName v2.7" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  - ISO 27001 & NIST CSF Compliance Assessment" -ForegroundColor Cyan
Write-Host "  - Vulnerability Assessment" -ForegroundColor Cyan
Write-Host "  - Penetration Testing Simulation" -ForegroundColor Cyan
Write-Host "  - Detailed HTML Report with Visual Analytics" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: This script requires Administrator privileges. Please run as Administrator." -ForegroundColor Red
    exit 1
}

Write-Host "Scan Configuration:" -ForegroundColor Yellow
Write-Host "  - Employee ID: $EmployeeId" -ForegroundColor White
Write-Host "  - Scan Depth: $ScanDepth" -ForegroundColor White
Write-Host "  - Pen Test Simulation: $($IncludePenTest.ToString().ToUpper())" -ForegroundColor White
Write-Host "  - Output Path: $OutputPath" -ForegroundColor White
Write-Host ""

Write-Host "Collecting system information..." -ForegroundColor Yellow
$hardwareData = Get-HardwareInventory
$systemData   = Get-SystemInformation
$userData     = Get-SimpleUserInformation

Write-Host "Performing security compliance checks..." -ForegroundColor Yellow
$securityChecks = Invoke-SecurityChecks

Write-Host "Running vulnerability assessment..." -ForegroundColor Yellow
$vulnerabilities = Invoke-VulnerabilityAssessment

$penTestResults = @()
if ($IncludePenTest) {
    Write-Host "Running penetration testing simulations..." -ForegroundColor Yellow
    $penTestResults = Invoke-PenetrationTesting
}

Write-Host "Generating comprehensive security report..." -ForegroundColor Yellow
New-SecurityReport `
    -Hardware $hardwareData `
    -System $systemData `
    -Users $userData `
    -SecurityChecks $securityChecks `
    -Vulnerabilities $vulnerabilities `
    -PenTestResults $penTestResults `
    -EmployeeId $EmployeeIdSafe

Write-Host ""
Write-Host "Audit complete!" -ForegroundColor Green
Write-Host "Report saved to: $OutputPath" -ForegroundColor Green
Write-Host "Security Score: $VulnerabilityScore/100" -ForegroundColor Green
Write-Host ""

$openReport = Read-Host "Open report in browser? (Y/N)"
if ($openReport -match '^(Y|y)$') {
    try { Invoke-Item $OutputPath } catch { Write-Host "Open manually: $OutputPath" -ForegroundColor Yellow }
}

#endregion
