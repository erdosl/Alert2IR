#requires -Version 5.1
<#
.SYNOPSIS
Performs read-only validation of the exact Alert2IR local/effective NRPT rule.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$ExpectedComputerName,

    [Parameter()]
    [string]$ExpectedHostOnlyAddress,

    [Parameter()]
    [string]$ContractPath = (Join-Path $PSScriptRoot '..\..\..\config\windows\nrpt-alert2ir.test.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$contract = Get-Content -LiteralPath (Resolve-Path -LiteralPath $ContractPath).Path -Raw | ConvertFrom-Json

if ($ExpectedComputerName -and $env:COMPUTERNAME -ne $ExpectedComputerName) {
    throw "Unexpected endpoint identity: $env:COMPUTERNAME"
}
if ($ExpectedHostOnlyAddress) {
    $addresses = @(Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object IPAddress)
    if ($ExpectedHostOnlyAddress -notin $addresses) {
        throw "Expected host-only address is absent: $ExpectedHostOnlyAddress"
    }
}

$local = @(Get-DnsClientNrptRule | Where-Object DisplayName -eq $contract.display_name)
if ($local.Count -ne 1) { throw 'Expected exactly one local Alert2IR NRPT rule.' }
$localNamespace = @($local[0].Namespace)
$localServers = @($local[0].NameServers)
if ($localNamespace.Count -ne 1 -or $localNamespace[0] -ne $contract.namespace -or
    $localServers.Count -ne 1 -or $localServers[0] -ne @($contract.name_servers)[0] -or
    [bool]$local[0].DirectAccessEnabled -or [bool]$local[0].DnsSecValidationRequired) {
    throw 'The local Alert2IR NRPT rule differs from the contract.'
}

$effective = @(Get-DnsClientNrptPolicy -Effective | Where-Object {
    @($_.Namespace) -contains $contract.namespace
})
if ($effective.Count -ne 1 -or @($effective[0].NameServers).Count -ne 1 -or
    @($effective[0].NameServers)[0] -ne @($contract.name_servers)[0] -or
    [bool]$effective[0].DirectAccessEnabled -or [bool]$effective[0].DnsSecValidationRequired) {
    throw 'The effective Alert2IR NRPT policy differs from the contract.'
}

[ordered]@{
    computer_name = $env:COMPUTERNAME
    host_only_address = $ExpectedHostOnlyAddress
    local_rule_name = [string]$local[0].Name
    namespace = $contract.namespace
    name_servers = @($contract.name_servers)
    interface_dns = @(Get-DnsClientServerAddress | ForEach-Object {
        [ordered]@{
            interface_alias = $_.InterfaceAlias
            interface_index = $_.InterfaceIndex
            address_family = [int]$_.AddressFamily
            server_addresses = @($_.ServerAddresses)
        }
    })
    nrpt_global = Get-DnsClientNrptGlobal
    valid = $true
} | ConvertTo-Json -Depth 8
