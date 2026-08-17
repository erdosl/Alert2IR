#requires -Version 5.1
<#
.SYNOPSIS
Inspects, applies, or removes the exact local Alert2IR NRPT rule.

.DESCRIPTION
The helper fails closed on overlapping local/effective policy. It never changes
execution policy, interface DNS, routing, cache state, DirectAccess, VPN, or GPO.
The live lab may use equivalent inline administrative commands when Restricted
execution policy prevents script-file execution.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Inspect', 'Apply', 'Remove')]
    [string]$Mode,

    [Parameter()]
    [string]$ContractPath = (Join-Path $PSScriptRoot '..\..\..\config\windows\nrpt-alert2ir.test.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Contract {
    $resolved = (Resolve-Path -LiteralPath $ContractPath).Path
    $contract = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json
    if ($contract.display_name -ne 'Alert2IR-Lab-DNS-alert2ir.test' -or
        $contract.namespace -ne '.alert2ir.test' -or
        @($contract.name_servers).Count -ne 1 -or
        @($contract.name_servers)[0] -ne '192.168.56.64' -or
        $contract.policy_store -ne 'local' -or
        $contract.dnssec_required -ne $false -or
        $contract.direct_access -ne $false) {
        throw 'The NRPT contract is not the reviewed Alert2IR contract.'
    }
    return $contract
}

function Convert-Namespace([object]$Value) {
    return ([string]$Value).Trim().TrimEnd('.').ToLowerInvariant()
}

function Get-Namespaces([object]$Rule) {
    return @($Rule.Namespace | ForEach-Object { Convert-Namespace $_ })
}

function Get-BooleanProperty([object]$Value, [string[]]$Names) {
    foreach ($name in $Names) {
        if ($null -ne $Value.PSObject.Properties[$name]) {
            return [bool]$Value.$name
        }
    }
    return $false
}

function Test-ExactRule([object]$Rule, [object]$Contract) {
    $namespaces = @(Get-Namespaces $Rule)
    $servers = @($Rule.NameServers | ForEach-Object { [string]$_ })
    $directAccess = Get-BooleanProperty $Rule @('DirectAccessEnabled', 'DirectAccess', 'DA')
    $dnssec = Get-BooleanProperty $Rule @('DnsSecValidationRequired', 'DnsSecEnabled', 'DnsSec')
    return (
        $Rule.DisplayName -eq $Contract.display_name -and
        $namespaces.Count -eq 1 -and
        $namespaces[0] -eq $Contract.namespace -and
        $servers.Count -eq 1 -and
        $servers[0] -eq @($Contract.name_servers)[0] -and
        -not $directAccess -and
        -not $dnssec
    )
}

function Test-NamespaceAffectsOwnedZone([string]$Namespace, [string]$OwnedNamespace) {
    $candidate = Convert-Namespace $Namespace
    $owned = Convert-Namespace $OwnedNamespace
    if ($candidate -eq '.' -or $candidate -eq '') { return $true }
    if ($candidate -eq '.test' -or $candidate -eq 'test') { return $true }
    if ($candidate -eq $owned) { return $true }
    if ($candidate.EndsWith($owned)) { return $true }
    return $false
}

function Get-ConflictAssessment([object[]]$LocalRules, [object[]]$EffectiveRules, [object]$Contract) {
    $conflicts = [System.Collections.Generic.List[object]]::new()
    $displayMatches = @($LocalRules | Where-Object DisplayName -eq $Contract.display_name)
    if ($displayMatches.Count -gt 1) {
        $conflicts.Add([ordered]@{ type = 'duplicate_display_name'; detail = $Contract.display_name })
    }

    foreach ($rule in $LocalRules) {
        $namespaces = @(Get-Namespaces $rule)
        foreach ($namespace in $namespaces) {
            if (-not (Test-NamespaceAffectsOwnedZone $namespace $Contract.namespace)) { continue }
            if (Test-ExactRule $rule $Contract) { continue }
            $kind = if ($namespace -eq '.test' -or $namespace -eq 'test') {
                'broad_test_rule'
            } elseif ($namespace -eq '.' -or $namespace -eq '') {
                'root_catch_all_rule'
            } elseif ($namespace -eq $Contract.namespace) {
                'same_namespace_conflict'
            } elseif ($namespace.EndsWith($Contract.namespace)) {
                'more_specific_conflict'
            } else {
                'overlapping_local_conflict'
            }
            if (Get-BooleanProperty $rule @('DirectAccessEnabled', 'DirectAccess', 'DA')) {
                $kind = 'directaccess_or_vpn_conflict'
            }
            $conflicts.Add([ordered]@{ type = $kind; detail = $namespace })
        }
    }

    foreach ($rule in $EffectiveRules) {
        foreach ($namespace in @(Get-Namespaces $rule)) {
            if (-not (Test-NamespaceAffectsOwnedZone $namespace $Contract.namespace)) { continue }
            if (Get-BooleanProperty $rule @('DirectAccessEnabled', 'DirectAccess', 'DA')) {
                $conflicts.Add([ordered]@{ type = 'directaccess_or_vpn_conflict'; detail = $namespace })
                continue
            }
            if (Get-BooleanProperty $rule @('DnsSecValidationRequired', 'DnsSecEnabled', 'DnsSec')) {
                $conflicts.Add([ordered]@{ type = 'gpo_or_effective_policy_conflict'; detail = $namespace })
                continue
            }
            $matchingLocal = @($LocalRules | Where-Object {
                (Get-Namespaces $_) -contains $namespace -and
                @($_.NameServers) -join ',' -eq @($rule.NameServers) -join ','
            })
            if ($matchingLocal.Count -eq 0) {
                $conflicts.Add([ordered]@{ type = 'gpo_or_effective_policy_conflict'; detail = $namespace })
            }
        }
    }
    return @($conflicts)
}

function Get-SanitizedState([object]$Contract) {
    $localRules = @(Get-DnsClientNrptRule)
    $effectiveRules = @(Get-DnsClientNrptPolicy -Effective)
    $matches = @($localRules | Where-Object DisplayName -eq $Contract.display_name)
    $conflicts = @(Get-ConflictAssessment $localRules $effectiveRules $Contract)
    return [ordered]@{
        computer_name = $env:COMPUTERNAME
        display_name = $Contract.display_name
        local_match_count = $matches.Count
        local_matches = @($matches | ForEach-Object {
            [ordered]@{
                name = [string]$_.Name
                namespace = @(Get-Namespaces $_)
                name_servers = @($_.NameServers | ForEach-Object { [string]$_ })
                exact = (Test-ExactRule $_ $Contract)
            }
        })
        effective_owned_rules = @($effectiveRules | Where-Object {
            $rule = $_
            @(Get-Namespaces $rule | Where-Object { Test-NamespaceAffectsOwnedZone $_ $Contract.namespace }).Count -gt 0
        } | ForEach-Object {
            [ordered]@{ namespace = @(Get-Namespaces $_); name_servers = @($_.NameServers | ForEach-Object { [string]$_ }) }
        })
        conflicts = $conflicts
    }
}

$contract = Get-Contract
$local = @(Get-DnsClientNrptRule)
$effective = @(Get-DnsClientNrptPolicy -Effective)
$conflicts = @(Get-ConflictAssessment $local $effective $contract)

switch ($Mode) {
    'Inspect' {
        Get-SanitizedState $contract | ConvertTo-Json -Depth 8
    }
    'Apply' {
        if ($conflicts.Count -gt 0) {
            throw ('Refusing NRPT apply because conflicts exist: {0}' -f (($conflicts.type | Sort-Object -Unique) -join ', '))
        }
        $existing = @($local | Where-Object DisplayName -eq $contract.display_name)
        if ($existing.Count -eq 1 -and (Test-ExactRule $existing[0] $contract)) {
            Get-SanitizedState $contract | ConvertTo-Json -Depth 8
            break
        }
        if ($existing.Count -ne 0) {
            throw 'Refusing ambiguous NRPT apply.'
        }
        $params = @{
            Namespace = $contract.namespace
            NameServers = @($contract.name_servers)[0]
            DisplayName = $contract.display_name
            Comment = $contract.comment
        }
        Add-DnsClientNrptRule @params
        $created = @(Get-DnsClientNrptRule | Where-Object DisplayName -eq $contract.display_name)
        if ($created.Count -ne 1 -or -not (Test-ExactRule $created[0] $contract)) {
            throw 'NRPT apply did not produce exactly one reviewed local rule.'
        }
        Get-SanitizedState $contract | ConvertTo-Json -Depth 8
    }
    'Remove' {
        $matches = @(Get-DnsClientNrptRule | Where-Object DisplayName -eq $contract.display_name)
        if ($matches.Count -ne 1) {
            throw 'Refusing ambiguous NRPT rollback.'
        }
        if (-not (Test-ExactRule $matches[0] $contract)) {
            throw 'Refusing to remove a rule that differs from the reviewed contract.'
        }
        $ruleName = [string]$matches[0].Name
        Remove-DnsClientNrptRule -Name $ruleName -Confirm:$false
        if (@(Get-DnsClientNrptRule | Where-Object DisplayName -eq $contract.display_name).Count -ne 0) {
            throw 'The exact NRPT rule remained after removal.'
        }
        [ordered]@{ removed_name = $ruleName; interface_dns_changed = $false } | ConvertTo-Json
    }
}
