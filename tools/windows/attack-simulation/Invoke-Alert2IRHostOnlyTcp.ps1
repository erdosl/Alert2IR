[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $RunId,

    [Parameter(Mandatory = $true)]
    [System.Net.IPAddress] $DestinationAddress,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 65535)]
    [int] $DestinationPort,

    [ValidateRange(250, 5000)]
    [int] $TimeoutMilliseconds = 2000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$parsedRunId = [guid]::Empty
if (-not [guid]::TryParseExact($RunId, 'D', [ref] $parsedRunId)) {
    throw 'RunId must be a canonical UUID.'
}

if ($DestinationAddress.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
    throw 'Only an IPv4 host-only destination is permitted.'
}

$octets = $DestinationAddress.GetAddressBytes()
if ($octets[0] -ne 192 -or $octets[1] -ne 168 -or $octets[2] -ne 56) {
    throw 'DestinationAddress must be inside the owned 192.168.56.0/24 host-only network.'
}
$ownedAddresses = @(
    '192.168.56.60',
    '192.168.56.61',
    '192.168.56.62',
    '192.168.56.63',
    '192.168.56.64',
    '192.168.56.65'
)
if ($DestinationAddress.IPAddressToString -notin $ownedAddresses) {
    throw 'DestinationAddress must identify an exact system authorized by LAB_SCOPE.md.'
}

$client = [System.Net.Sockets.TcpClient]::new()
try {
    $connect = $client.ConnectAsync($DestinationAddress, $DestinationPort)
    if (-not $connect.Wait($TimeoutMilliseconds)) {
        throw 'The single bounded TCP connection attempt timed out.'
    }
    $connect.GetAwaiter().GetResult()
    if (-not $client.Connected) {
        throw 'The single bounded TCP connection attempt did not connect.'
    }
}
finally {
    $client.Dispose()
}
