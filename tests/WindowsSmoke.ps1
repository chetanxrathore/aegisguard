#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$scanner = Join-Path $PSScriptRoot '..\src\AegisGuard.ps1'
$reportPath = Join-Path $env:TEMP ("aegisguard-{0}.html" -f [guid]::NewGuid())
Write-Host "Testing with PowerShell $($PSVersionTable.PSVersion) on $([Environment]::OSVersion.VersionString)"

try {
    & $scanner -EmployeeId 'CI-WINDOWS' -ScanDepth Comprehensive -OutputPath $reportPath -IncludePenTest:$false -NoPrompt
    $html = Get-Content -LiteralPath $reportPath -Raw -Encoding UTF8

    # Check that the report contains evidence from this runner.
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $caption = [System.Net.WebUtility]::HtmlEncode($os.Caption)
    if (-not $html.Contains("<td>Caption</td><td>$caption</td>")) {
        throw 'The report is missing the actual Windows product name.'
    }
    if (-not $html.TrimEnd().EndsWith('</html>') -or -not $html.Contains('CI-WINDOWS')) {
        throw 'The audit did not produce a complete report for this run.'
    }

    # The runner's posture may change when GitHub refreshes its image.
    $rows = [regex]::Matches($html, "<td>(SEC-\d+)</td><td>[^<]+</td><td class='[^']+'>(PASS|PARTIAL|FAIL|UNKNOWN)</td>")
    $actualIds = @($rows | ForEach-Object { $_.Groups[1].Value } | Sort-Object)
    $expectedIds = @(1..17 | ForEach-Object { 'SEC-{0:D3}' -f $_ })
    if (($actualIds -join ',') -ne ($expectedIds -join ',')) {
        throw "Unexpected set of completed checks. Found: $($actualIds -join ', ')"
    }
    $unknown = @($rows | Where-Object { $_.Groups[2].Value -eq 'UNKNOWN' }).Count
    $passed = @($rows | Where-Object { $_.Groups[2].Value -eq 'PASS' }).Count
    $assessed = $rows.Count - $unknown
    if (-not $html.Contains("$assessed/17 selected checks assessed ($unknown unknown)") -or
        -not $html.Contains("$passed/$assessed assessed checks passed")) {
        throw 'The report summary disagrees with the individual check results.'
    }
    Write-Host "Verified Windows inventory and $($rows.Count) posture check results."
} finally {
    if (Test-Path -LiteralPath $reportPath) {
        Remove-Item -LiteralPath $reportPath -Force
    }
}
