[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Preflight', 'Execute', 'Cleanup', 'VerifyPost')]
    [string] $Action,

    [Parameter(Mandatory = $true)]
    [string] $BaseFilePath,

    [Parameter(Mandatory = $true)]
    [string] $StreamName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$baseMatch = [regex]::Match(
    $BaseFilePath,
    '^C:\\Windows\\Temp\\Alert2IR-ADS-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.txt$',
    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
)
$streamMatch = [regex]::Match(
    $StreamName,
    '^Alert2IR-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$',
    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
)
if (-not $baseMatch.Success -or -not $streamMatch.Success) {
    throw 'The base file and stream must use the reviewed run-scoped names.'
}
if ($baseMatch.Groups[1].Value -ne $streamMatch.Groups[1].Value) {
    throw 'The base file and stream must use the same run identity.'
}

$streamPath = "${BaseFilePath}:$StreamName"

function Assert-Alert2IRAdsAbsent {
    if ([System.IO.File]::Exists($BaseFilePath) -or [System.IO.File]::Exists($streamPath)) {
        throw 'The exact run-scoped ADS resource is not absent.'
    }
}

switch ($Action) {
    'Preflight' {
        Assert-Alert2IRAdsAbsent
    }
    'Execute' {
        Assert-Alert2IRAdsAbsent
        [System.IO.File]::WriteAllText($BaseFilePath, 'Alert2IR benign ADS base marker')
        [System.IO.File]::WriteAllText($streamPath, 'Alert2IR benign ADS stream marker')
    }
    'Cleanup' {
        if ([System.IO.File]::Exists($BaseFilePath)) {
            Remove-Item -LiteralPath $BaseFilePath -Force
        }
    }
    'VerifyPost' {
        Assert-Alert2IRAdsAbsent
    }
}
