#Requires -RunAsAdministrator
param([string]$ReportPath)

$ErrorActionPreference = 'Stop'
$scanner = Join-Path $PSScriptRoot '..\src\AegisGuard.ps1'
$temporaryReport = -not $ReportPath
if ($temporaryReport) {
    $ReportPath = Join-Path $env:TEMP ("aegisguard-{0}.html" -f [guid]::NewGuid())
}
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
    $rows = [regex]::Matches($html, "<td>(?<id>SEC-\d+)</td><td>(?<name>[^<]+)</td><td class='[^']+'>(?<result>PASS|PARTIAL|FAIL|UNKNOWN)</td>")
    $actualIds = @($rows | ForEach-Object { $_.Groups['id'].Value } | Sort-Object)
    $expectedIds = @(1..17 | ForEach-Object { 'SEC-{0:D3}' -f $_ })
    if (($actualIds -join ',') -ne ($expectedIds -join ',')) {
        throw "Unexpected set of completed checks. Found: $($actualIds -join ', ')"
    }
    $unknown = @($rows | Where-Object { $_.Groups['result'].Value -eq 'UNKNOWN' }).Count
    $passed = @($rows | Where-Object { $_.Groups['result'].Value -eq 'PASS' }).Count
    $assessed = $rows.Count - $unknown
    if (-not $html.Contains("$assessed/17 selected checks assessed ($unknown unknown)") -or
        -not $html.Contains("$passed/$assessed assessed checks passed")) {
        throw 'The report summary disagrees with the individual check results.'
    }
    Write-Host "Verified Windows inventory and $($rows.Count) posture check results."
    if ($env:GITHUB_STEP_SUMMARY) {
        $summary = @(
            '### Windows audit results'
            ''
            "$passed of $assessed assessed checks passed. $unknown of $($rows.Count) checks returned UNKNOWN."
            ''
            '<details><summary>View individual checks</summary>'
            ''
            '| ID | Check | Result |'
            '| --- | --- | --- |'
            foreach ($row in $rows) {
                '| {0} | {1} | {2} |' -f $row.Groups['id'].Value, $row.Groups['name'].Value.Replace('|', '\|'), $row.Groups['result'].Value
            }
            ''
            '</details>'
        )
        $summary | Out-File -LiteralPath $env:GITHUB_STEP_SUMMARY -Encoding utf8 -Append
    }
} finally {
    if ($temporaryReport -and (Test-Path -LiteralPath $ReportPath)) {
        Remove-Item -LiteralPath $reportPath -Force
    }
}
