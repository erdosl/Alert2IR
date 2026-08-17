[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Preflight', 'Positive', 'Control', 'Cleanup', 'VerifyPost')]
    [string] $Action,

    [Parameter(Mandatory = $true)]
    [string] $RunId,

    [Parameter(Mandatory = $true)]
    [string] $ScriptPath,

    [Parameter(Mandatory = $true)]
    [string] $Marker,

    [ValidateRange(0, 2147483647)]
    [int] $ChildProcessId = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$parsedRunId = [guid]::Empty
if (-not [guid]::TryParseExact($RunId, 'D', [ref] $parsedRunId)) {
    throw 'RunId must be a canonical UUID.'
}

$expectedScriptPath = "C:\Windows\Temp\Alert2IR-Ancestry-$RunId.vbs"
$expectedMarker = "Alert2IR-Ancestry-$RunId"
if ($ScriptPath -cne $expectedScriptPath -or $Marker -cne $expectedMarker) {
    throw 'The script path and marker must match the exact run identity.'
}

$templatePath = Join-Path -Path $PSScriptRoot -ChildPath 'Alert2IR-AncestryChild.vbs'
$templateSha256 = '7b094bf7aedf6260591a6d291a1ab66a1593d7ff1b12b876b1d8c6ea56d759c9'
$cscriptPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\cscript.exe'
$childPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'
$childCommand = "`$null = '$Marker'; Start-Sleep -Seconds 5"
$childArguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', "`"$childCommand`"")

function Assert-Alert2IRTemplate {
    $actualHash = (Get-FileHash -LiteralPath $templatePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -cne $templateSha256) {
        throw 'The reviewed ancestry child template hash does not match.'
    }
}

function Assert-Alert2IRScriptAbsent {
    if ([System.IO.File]::Exists($ScriptPath)) {
        throw 'The exact run-scoped ancestry script is not absent.'
    }
}

function Stop-Alert2IRExactChildIfPresent {
    if ($ChildProcessId -eq 0) {
        return
    }

    $child = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $ChildProcessId"
    if ($null -eq $child) {
        return
    }
    if ($child.ExecutablePath -cne $childPath -or
        $null -eq $child.CommandLine -or
        -not $child.CommandLine.Contains($Marker)) {
        throw 'The supplied process identity is not the exact reviewed ancestry child.'
    }
    Stop-Process -Id $ChildProcessId -Force
    Wait-Process -Id $ChildProcessId -ErrorAction SilentlyContinue
}

switch ($Action) {
    'Preflight' {
        Assert-Alert2IRTemplate
        Assert-Alert2IRScriptAbsent
    }
    'Positive' {
        Assert-Alert2IRTemplate
        Assert-Alert2IRScriptAbsent
        Copy-Item -LiteralPath $templatePath -Destination $ScriptPath
        $copiedHash = (Get-FileHash -LiteralPath $ScriptPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($copiedHash -cne $templateSha256) {
            throw 'The run-scoped ancestry script hash does not match the reviewed template.'
        }
        $process = Start-Process -FilePath $cscriptPath -ArgumentList @(
            '//B',
            '//NoLogo',
            $ScriptPath,
            "/marker:$Marker"
        ) -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            throw "The reviewed ancestry script exited $($process.ExitCode)."
        }
    }
    'Control' {
        Assert-Alert2IRScriptAbsent
        $process = Start-Process -FilePath $childPath -ArgumentList $childArguments -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            throw "The ancestry control child exited $($process.ExitCode)."
        }
    }
    'Cleanup' {
        Stop-Alert2IRExactChildIfPresent
        if ([System.IO.File]::Exists($ScriptPath)) {
            Remove-Item -LiteralPath $ScriptPath -Force
        }
    }
    'VerifyPost' {
        Assert-Alert2IRScriptAbsent
        if ($ChildProcessId -ne 0 -and $null -ne (Get-Process -Id $ChildProcessId -ErrorAction SilentlyContinue)) {
            throw 'The exact reviewed ancestry child remains active.'
        }
    }
}
