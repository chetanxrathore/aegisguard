$ErrorActionPreference = 'Stop'
$scanner = Join-Path $PSScriptRoot '../src/AegisGuard.ps1'

# Shadow the Windows cmdlet so each example exercises the public recheck command.
function Get-BitLockerVolume {
    [CmdletBinding()]
    param([string]$MountPoint)
    if ($MountPoint -ne 'D:') { throw "Unexpected mount point $MountPoint" }
    switch ($case.Provider) {
        'Denied' { throw [UnauthorizedAccessException]::new('Access denied') }
        'Missing' { throw [System.Management.Automation.CommandNotFoundException]::new('Cmdlet missing') }
        'Empty' { return }
    }
    [pscustomobject]@{
        VolumeStatus = $case.Encryption
        ProtectionStatus = $case.Protection
    }
}

$cases = @(
    @{ Encryption='FullyEncrypted'; Protection='On'; Expected='PASS' }
    @{ Encryption='FullyEncrypted'; Protection='Off'; Expected='FAIL' }
    @{ Encryption='FullyDecrypted'; Protection='Off'; Expected='FAIL' }
    @{ Encryption='EncryptionInProgress'; Protection='On'; Expected='FAIL' }
    @{ Encryption='FullyDecrypted'; Expected='FAIL' }
    @{ Encryption='FullyEncrypted'; Protection='Unknown'; Expected='UNKNOWN' }
    @{ Encryption='UnexpectedValue'; Protection='On'; Expected='UNKNOWN' }
    @{ Provider='Empty'; Expected='UNKNOWN'; Reason='returned no volume' }
    @{ Provider='Denied'; Expected='UNKNOWN'; Reason='Access denied' }
    @{ Provider='Missing'; Expected='UNKNOWN'; Reason='cmdlet is unavailable' }
)

$originalDrive = $env:SystemDrive
try {
    $env:SystemDrive = 'D:'
    foreach ($case in $cases) {
        $finding = & $scanner -CheckId SEC-012
        if ($finding.ID -ne 'SEC-012' -or $finding.Result -ne $case.Expected -or $finding.MountPoint -ne 'D:') {
            throw "Unexpected BitLocker finding for $($case | ConvertTo-Json -Compress): $($finding | ConvertTo-Json -Compress)"
        }
        if ($finding.VolumeStatus -ne [string]$case.Encryption -or $finding.ProtectionStatus -ne [string]$case.Protection) {
            throw 'Observed encryption and protection evidence did not match the fixture.'
        }
        if ($case.Reason -and -not $finding.Details.Contains($case.Reason)) {
            throw "Missing explanation for $($case.Provider): $($finding.Details)"
        }
    }
} finally {
    $env:SystemDrive = $originalDrive
}
Write-Host "Verified $($cases.Count) BitLocker cases."
