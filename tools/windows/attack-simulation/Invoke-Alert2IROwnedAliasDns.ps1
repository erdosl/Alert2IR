[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $RunId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $QueryName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $OwnedSuffix
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$parsedRunId = [guid]::Empty
if (-not [guid]::TryParseExact($RunId, 'D', [ref] $parsedRunId)) {
    throw 'RunId must be a canonical UUID.'
}

$canonicalName = $QueryName.TrimEnd('.').ToLowerInvariant()
$canonicalSuffix = $OwnedSuffix.TrimEnd('.').ToLowerInvariant()
if (-not $canonicalSuffix.StartsWith('.')) {
    throw 'OwnedSuffix must begin with a dot.'
}
if (-not $canonicalName.EndsWith($canonicalSuffix)) {
    throw 'QueryName must be beneath the reviewed owned lab suffix.'
}
if ($canonicalName.Contains('*') -or $canonicalName.Contains('..')) {
    throw 'QueryName contains an unsafe or ambiguous component.'
}

$answers = @(Resolve-DnsName -Name $canonicalName -Type A -DnsOnly -QuickTimeout -ErrorAction Stop)
$addresses = @($answers | Where-Object { $_.Type -eq 'A' } | ForEach-Object { [System.Net.IPAddress]::Parse($_.IPAddress) })
if ($addresses.Count -eq 0) {
    throw 'The owned alias did not return an IPv4 answer.'
}
$ownedAddresses = @(
    '192.168.56.60',
    '192.168.56.61',
    '192.168.56.62',
    '192.168.56.63',
    '192.168.56.64',
    '192.168.56.65'
)
foreach ($address in $addresses) {
    $octets = $address.GetAddressBytes()
    if ($address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or
        $octets[0] -ne 192 -or $octets[1] -ne 168 -or $octets[2] -ne 56) {
        throw 'The owned alias returned an address outside the host-only lab.'
    }
    if ($address.IPAddressToString -notin $ownedAddresses) {
        throw 'The owned alias returned an address not authorized by LAB_SCOPE.md.'
    }
}
