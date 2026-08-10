#requires -Version 5.1
<#
.SYNOPSIS
Collects a read-only Alert2IR Windows endpoint inventory.

.DESCRIPTION
Writes a versioned JSON inventory and, when available, sanitized diagnostic text
artifacts. The collector does not install, configure, enable, disable, start, or
stop anything.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputRoot = [System.IO.Path]::GetTempPath()
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:Warnings = [System.Collections.Generic.List[string]]::new()
$script:Errors = [System.Collections.Generic.List[string]]::new()
$timestamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$safeComputerName = ($env:COMPUTERNAME -replace '[^A-Za-z0-9_.-]', '_')
$outputDirectory = Join-Path $OutputRoot ("Alert2IR-EndpointInventory-{0}-{1}" -f $safeComputerName, $timestamp)
New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null

function Add-CheckError {
    param([string]$Check, [System.Management.Automation.ErrorRecord]$Record)
    $script:Errors.Add(("{0}: {1}" -f $Check, $Record.Exception.Message))
}

function Invoke-InventoryCheck {
    param(
        [string]$Name,
        [scriptblock]$ScriptBlock,
        $Default = $null
    )
    try { & $ScriptBlock } catch { Add-CheckError -Check $Name -Record $_; $Default }
}

function Convert-CimDate {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('o') }
    try { return ([Management.ManagementDateTimeConverter]::ToDateTime([string]$Value)).ToUniversalTime().ToString('o') } catch { return [string]$Value }
}

function Get-ExecutablePathFromCommandLine {
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $expanded = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    if ($expanded -match '^\s*"([^"]+\.(?:exe|sys))"') { return ($matches[1] -replace '^\\\?\?\\', '') }
    if ($expanded -match '^\s*([^\s]+\.(?:exe|sys))') { return ($matches[1] -replace '^\\\?\?\\', '') }
    return $null
}

function Get-FileEvidence {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $item = Get-Item -LiteralPath $Path
    $version = $item.VersionInfo
    [ordered]@{
        path = $item.FullName
        version = $version.FileVersion
        product_name = $version.ProductName
        company_name = $version.CompanyName
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
    }
}

function Get-PropertyValue {
    param($InputObject, [string]$Name)
    if ($null -eq $InputObject) { return $null }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function Invoke-ReadOnlyProcess {
    param([string]$FilePath, [string]$Arguments, [hashtable]$Environment)
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = $Arguments
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.CreateNoWindow = $true
    if ($Environment) {
        foreach ($name in $Environment.Keys) { $startInfo.EnvironmentVariables[$name] = [string]$Environment[$name] }
    }
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    [void]$process.Start()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    [ordered]@{ exit_code = $process.ExitCode; stdout = $stdout; stderr = $stderr }
}

function Protect-SplunkText {
    param([string]$Text)
    if ($null -eq $Text) { return $null }
    $sensitiveKey = '(?i)(password|passwd|passphrase|pass4SymmKey|secret|token|private[_ -]?key|credential|auth(?:entication)?(?:token)?|session[_ -]?key|api[_ -]?key|bearer)'
    $protectedLines = foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^\s*([^#;][^=]*)\s*=') {
            $key = $matches[1].Trim()
            if ($key -match $sensitiveKey) { "{0} = <REDACTED>" -f $key; continue }
        }
        if ($line -match $sensitiveKey -and $line -match '(?i)(=|:)') {
            '<REDACTED-SENSITIVE-LINE>'
            continue
        }
        $line
    }
    return ($protectedLines -join [Environment]::NewLine)
}

function Get-BtoolStanza {
    param([string]$Text, [string]$StanzaPattern)
    $currentStanza = $null
    $result = [System.Collections.Generic.List[object]]::new()
    foreach ($line in ($Text -split "`r?`n")) {
        $content = $line
        $source = $null
        if ($line -match '^([^\s].*?\.conf)\s+(.*)$') { $source = $matches[1]; $content = $matches[2] }
        if ($content -match '^\s*\[([^\]]+)\]\s*$') { $currentStanza = $matches[1]; continue }
        if ($currentStanza -match $StanzaPattern -and $content -match '^\s*([^=]+?)\s*=\s*(.*)$') {
            $result.Add([ordered]@{ stanza = $currentStanza; key = $matches[1].Trim(); value = $matches[2].Trim(); source = $source })
        }
    }
    return @($result)
}

$computerSystem = Invoke-InventoryCheck 'system.computer_system' { Get-CimInstance Win32_ComputerSystem }
$operatingSystem = Invoke-InventoryCheck 'system.operating_system' { Get-CimInstance Win32_OperatingSystem }
$osRegistry = Invoke-InventoryCheck 'system.os_registry' {
    $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    [ordered]@{
        ProductName = $cv.ProductName; DisplayVersion = $cv.DisplayVersion; EditionID = $cv.EditionID
        CurrentBuild = $cv.CurrentBuild; UBR = $cv.UBR
    }
}

$timeService = Invoke-InventoryCheck 'system.windows_time' {
    $service = Get-CimInstance Win32_Service -Filter "Name='W32Time'"
    $configured = & w32tm.exe /query /configuration 2>&1 | Out-String
    $source = & w32tm.exe /query /source 2>&1 | Out-String
    [ordered]@{
        status = $service.State; start_mode = $service.StartMode
        current_source = $source.Trim(); configured = $configured.Trim()
    }
}

$guestAdditions = Invoke-InventoryCheck 'system.virtualbox_guest_additions' {
    $guestService = Get-CimInstance Win32_Service -Filter "Name='VBoxService'"
    $guestExe = Get-ExecutablePathFromCommandLine $guestService.PathName
    [ordered]@{ present = ($null -ne $guestService); service_state = $guestService.State; executable = Get-FileEvidence $guestExe }
} ([ordered]@{ present = $false })

$puppet = Invoke-InventoryCheck 'system.puppet' {
    $puppetCommand = Get-Command puppet.exe -ErrorAction SilentlyContinue
    $puppetService = Get-CimInstance Win32_Service -Filter "Name='puppet'" -ErrorAction SilentlyContinue
    $puppetExe = if ($puppetCommand) { $puppetCommand.Source } elseif ($puppetService) { Get-ExecutablePathFromCommandLine $puppetService.PathName } else { $null }
    $version = $null
    if ($puppetExe) { $versionResult = Invoke-ReadOnlyProcess $puppetExe '--version'; $version = $versionResult.stdout.Trim() }
    $configCandidates = @('C:\ProgramData\PuppetLabs\puppet\etc\puppet.conf', 'C:\ProgramData\PuppetLabs\puppet\etc\puppet\puppet.conf')
    [ordered]@{
        installed = [bool]($puppetExe -or $puppetService); version = $version
        service = if ($puppetService) { [ordered]@{ state = $puppetService.State; start_mode = $puppetService.StartMode; account = $puppetService.StartName; image_path = $puppetService.PathName } } else { $null }
        config_presence = @($configCandidates | ForEach-Object { [ordered]@{ path = $_; exists = (Test-Path -LiteralPath $_ -PathType Leaf) } })
    }
} ([ordered]@{ installed = $false })

$networkAdapters = Invoke-InventoryCheck 'network.adapters' {
    @(Get-NetAdapter | Where-Object Status -eq 'Up' | Sort-Object ifIndex | ForEach-Object {
        [ordered]@{ name = $_.Name; interface_description = $_.InterfaceDescription; interface_index = $_.ifIndex; status = $_.Status; link_speed = [string]$_.LinkSpeed }
    })
} @()
$ipConfigurations = Invoke-InventoryCheck 'network.ip_configuration' {
    @(Get-NetIPConfiguration | Where-Object {
        $netAdapter = Get-PropertyValue $_ 'NetAdapter'
        $adapterStatus = Get-PropertyValue $netAdapter 'Status'
        $null -eq $adapterStatus -or $adapterStatus -eq 'Up'
    } | ForEach-Object {
        $ifIndex = Get-PropertyValue $_ 'InterfaceIndex'
        $v4Interfaces = if ($null -ne $ifIndex) { @(Get-NetIPInterface -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction Stop) } else { @() }
        $ipv4Addresses = @(Get-PropertyValue $_ 'IPv4Address')
        $ipv4Gateways = @(Get-PropertyValue $_ 'IPv4DefaultGateway')
        $dnsServerObjects = @(Get-PropertyValue $_ 'DNSServer')
        [ordered]@{
            interface_alias = Get-PropertyValue $_ 'InterfaceAlias'; interface_index = $ifIndex
            ipv4 = @($ipv4Addresses | Where-Object { $null -ne $_ } | ForEach-Object {
                [ordered]@{ address = Get-PropertyValue $_ 'IPAddress'; prefix_length = Get-PropertyValue $_ 'PrefixLength' }
            })
            dhcp = @($v4Interfaces | ForEach-Object { [string](Get-PropertyValue $_ 'Dhcp') } | Where-Object { $_ } | Select-Object -Unique)
            default_gateways = @($ipv4Gateways | Where-Object { $null -ne $_ } | ForEach-Object { Get-PropertyValue $_ 'NextHop' } | Where-Object { $_ })
            dns_servers = @($dnsServerObjects | Where-Object { $null -ne $_ } | ForEach-Object { @(Get-PropertyValue $_ 'ServerAddresses') } | Where-Object { $_ })
        }
    })
} @()
$connectionProfiles = Invoke-InventoryCheck 'network.connection_profiles' {
    @(Get-NetConnectionProfile | ForEach-Object { [ordered]@{ name = $_.Name; interface_alias = $_.InterfaceAlias; interface_index = $_.InterfaceIndex; category = [string]$_.NetworkCategory; ipv4_connectivity = [string]$_.IPv4Connectivity } })
} @()
$firewallProfiles = Invoke-InventoryCheck 'network.firewall_profiles' {
    @(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ name = $_.Name; enabled = $_.Enabled; default_inbound_action = [string]$_.DefaultInboundAction; default_outbound_action = [string]$_.DefaultOutboundAction } })
} @()
$nameResolution = foreach ($name in @('splunk', 'splunk.lab.test')) {
    Invoke-InventoryCheck ("network.resolve.{0}" -f $name) {
        try {
            $resolvedAddresses = @([System.Net.Dns]::GetHostAddresses($name) | ForEach-Object { $_.IPAddressToString })
            [ordered]@{ name = $name; attempted = $true; succeeded = $true; addresses = $resolvedAddresses; failure_reason = $null }
        } catch {
            $resolutionException = $_.Exception
            while ($resolutionException.InnerException) { $resolutionException = $resolutionException.InnerException }
            if ($resolutionException -is [System.Net.Sockets.SocketException]) {
                $failureReason = switch ($resolutionException.SocketErrorCode) {
                    ([System.Net.Sockets.SocketError]::HostNotFound) { 'host_not_found'; break }
                    ([System.Net.Sockets.SocketError]::NoData) { 'host_not_found'; break }
                    default { $resolutionException.SocketErrorCode.ToString().ToLowerInvariant() }
                }
                [ordered]@{ name = $name; attempted = $true; succeeded = $false; addresses = @(); failure_reason = $failureReason }
            } else {
                throw
            }
        }
    } ([ordered]@{ name = $name; attempted = $true; succeeded = $false; addresses = @(); failure_reason = 'collection_failed' })
}
$tcpTest = Invoke-InventoryCheck 'network.tcp_192.168.56.61_9997' {
    $test = Test-NetConnection -ComputerName '192.168.56.61' -Port 9997 -InformationLevel Detailed -WarningAction SilentlyContinue
    if ($null -eq $test) { throw 'Test-NetConnection returned no result.' }
    $nameResolutionResults = @(Get-PropertyValue $test 'NameResolutionResults')
    $remoteAddress = Get-PropertyValue $test 'RemoteAddress'
    $sourceAddress = Get-PropertyValue $test 'SourceAddress'
    [ordered]@{
        target = '192.168.56.61'; port = 9997; attempted = $true
        computer_name = Get-PropertyValue $test 'ComputerName'
        remote_address = if ($null -ne $remoteAddress) { [string]$remoteAddress } else { $null }
        remote_port = Get-PropertyValue $test 'RemotePort'
        interface_alias = Get-PropertyValue $test 'InterfaceAlias'
        source_address = if ($null -ne $sourceAddress) { [string]$sourceAddress } else { $null }
        succeeded = Get-PropertyValue $test 'TcpTestSucceeded'
        name_resolution_results = @($nameResolutionResults | Where-Object { $null -ne $_ } | ForEach-Object {
            $address = Get-PropertyValue $_ 'IPAddressToString'
            if ($null -ne $address) { $address } else { [string]$_ }
        })
    }
}
$route = Invoke-InventoryCheck 'network.route_to_splunk' {
    $routeResults = @(Find-NetRoute -RemoteIPAddress '192.168.56.61')
    if ($routeResults.Count -eq 0) { throw 'Find-NetRoute returned no result.' }
    $routeCandidates = @($routeResults | Where-Object { $null -ne $_ -and $_.PSObject.Properties['DestinationPrefix'] } | ForEach-Object {
        [ordered]@{
            interface_index = Get-PropertyValue $_ 'InterfaceIndex'; interface_alias = Get-PropertyValue $_ 'InterfaceAlias'
            destination_prefix = Get-PropertyValue $_ 'DestinationPrefix'; next_hop = Get-PropertyValue $_ 'NextHop'
            route_metric = Get-PropertyValue $_ 'RouteMetric'; interface_metric = Get-PropertyValue $_ 'InterfaceMetric'
        }
    })
    $localAddressCandidates = @($routeResults | Where-Object { $null -ne $_ -and $_.PSObject.Properties['IPAddress'] } | ForEach-Object {
        $ipAddress = Get-PropertyValue $_ 'IPAddress'
        [ordered]@{
            ip_address = if ($null -ne $ipAddress) { [string]$ipAddress } else { $null }; prefix_length = Get-PropertyValue $_ 'PrefixLength'
            interface_index = Get-PropertyValue $_ 'InterfaceIndex'; interface_alias = Get-PropertyValue $_ 'InterfaceAlias'
        }
    })
    if ($routeCandidates.Count -eq 0 -and $localAddressCandidates.Count -eq 0) { throw 'Find-NetRoute returned no recognizable route or local-address objects.' }
    $selectedRoute = $routeCandidates | Select-Object -First 1
    $selectedAddress = $localAddressCandidates | Select-Object -First 1
    [ordered]@{
        remote_address = '192.168.56.61'
        source_address = if ($selectedAddress) { $selectedAddress.ip_address } else { $null }
        interface_index = if ($selectedRoute) { $selectedRoute.interface_index } elseif ($selectedAddress) { $selectedAddress.interface_index } else { $null }
        interface_alias = if ($selectedRoute) { $selectedRoute.interface_alias } elseif ($selectedAddress) { $selectedAddress.interface_alias } else { $null }
        destination_prefix = if ($selectedRoute) { $selectedRoute.destination_prefix } else { $null }
        next_hop = if ($selectedRoute) { $selectedRoute.next_hop } else { $null }
        route_metric = if ($selectedRoute) { $selectedRoute.route_metric } else { $null }
        interface_metric = if ($selectedRoute) { $selectedRoute.interface_metric } else { $null }
        route_candidates = $routeCandidates; local_address_candidates = $localAddressCandidates
    }
}
$tcpConnections = Invoke-InventoryCheck 'network.tcp_connections_9997' {
    @(Get-NetTCPConnection -RemotePort 9997 -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ state = [string]$_.State; local_address = $_.LocalAddress; local_port = $_.LocalPort; remote_address = $_.RemoteAddress; remote_port = $_.RemotePort; owning_process = $_.OwningProcess } })
} @()

$sysmonFeature = Invoke-InventoryCheck 'sysmon.optional_feature' {
    $feature = Get-WindowsOptionalFeature -Online -FeatureName Sysmon -ErrorAction SilentlyContinue
    if ($feature) { [ordered]@{ present = $true; feature_name = $feature.FeatureName; state = [string]$feature.State } } else { [ordered]@{ present = $false; state = 'Absent' } }
} ([ordered]@{ present = $false; state = 'Unknown' })
$sysmonServices = Invoke-InventoryCheck 'sysmon.services_and_drivers' {
    @(Get-CimInstance Win32_Service | Where-Object { $_.Name -match '(?i)sysmon' -or $_.DisplayName -match '(?i)sysmon' } | ForEach-Object {
        [ordered]@{ kind = 'service'; name = $_.Name; display_name = $_.DisplayName; state = $_.State; start_mode = $_.StartMode; account = $_.StartName; image_path = $_.PathName }
    }) + @(Get-CimInstance Win32_SystemDriver | Where-Object { $_.Name -match '(?i)sysmon' -or $_.DisplayName -match '(?i)sysmon' } | ForEach-Object {
        [ordered]@{ kind = 'driver'; name = $_.Name; display_name = $_.DisplayName; state = $_.State; start_mode = $_.StartMode; image_path = $_.PathName }
    })
} @()
$sysmonFiles = [System.Collections.Generic.List[object]]::new()
foreach ($entry in $sysmonServices) {
    $candidate = Get-ExecutablePathFromCommandLine $entry.image_path
    if (-not $candidate -and $entry.image_path) { $candidate = [Environment]::ExpandEnvironmentVariables(([string]$entry.image_path -replace '^\\SystemRoot', $env:SystemRoot)) }
    $evidence = Invoke-InventoryCheck ("sysmon.file.{0}" -f $entry.name) { Get-FileEvidence $candidate }
    if ($evidence) { $sysmonFiles.Add($evidence) }
}
$sysmonExe = $sysmonFiles | Where-Object { $_.path -match '(?i)sysmon(?:64)?\.exe$' } | Select-Object -First 1
$sysmonImplementation = if ([string]$sysmonFeature.state -match '^Enabled') {
    'built_in_windows_sysmon'
} elseif ($sysmonFiles.Count -gt 0 -or @($sysmonServices).Count -gt 0) {
    'standalone_sysinternals_sysmon_candidate'
} else {
    'no_installed_sysmon_evidence'
}
$sysmonInspection = [ordered]@{ configuration_artifact = $null; schema_artifact = $null }
if ($sysmonExe) {
    foreach ($inspection in @(@{ Name = 'configuration'; Arguments = '-c'; File = 'sysmon-current-configuration.txt' }, @{ Name = 'schema'; Arguments = '-s'; File = 'sysmon-schema.txt' })) {
        $result = Invoke-InventoryCheck ("sysmon.inspect.{0}" -f $inspection.Name) { Invoke-ReadOnlyProcess $sysmonExe.path $inspection.Arguments }
        if ($result) {
            $artifactPath = Join-Path $outputDirectory $inspection.File
            @($result.stdout, $result.stderr) -join [Environment]::NewLine | Set-Content -LiteralPath $artifactPath -Encoding UTF8
            $sysmonInspection[("{0}_artifact" -f $inspection.Name)] = [ordered]@{ file = $inspection.File; exit_code = $result.exit_code }
        }
    }
}
$sysmonLog = Invoke-InventoryCheck 'sysmon.event_log' {
    $log = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
    $boundedEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational' } -MaxEvents 10000 -ErrorAction SilentlyContinue)
    $newest = $boundedEvents | Select-Object -First 1
    [ordered]@{
        exists = $true; enabled = $log.IsEnabled; maximum_size_bytes = $log.MaximumSizeInBytes
        log_mode = [string]$log.LogMode; is_log_full = $log.IsLogFull; record_count = $log.RecordCount
        newest_event_utc = if ($newest) { $newest.TimeCreated.ToUniversalTime().ToString('o') } else { $null }
        newest_record_id = if ($newest) { $newest.RecordId } else { $null }
        aggregate_event_limit = 10000
        aggregate_is_bounded = ($log.RecordCount -gt 10000)
        event_id_counts = @($boundedEvents | Group-Object Id | Sort-Object { [int]$_.Name } | ForEach-Object { [ordered]@{ event_id = [int]$_.Name; count = $_.Count } })
    }
} ([ordered]@{ exists = $false })

$splunkService = Invoke-InventoryCheck 'splunk.service' { Get-CimInstance Win32_Service -Filter "Name='SplunkForwarder'" }
$eventLogReadersSid = 'S-1-5-32-573'
$splunkEventLogAccess = [ordered]@{
    attempted = $false
    service_identity = if ($splunkService) { Get-PropertyValue $splunkService 'StartName' } else { $null }
    service_identity_sid = $null
    event_log_readers_sid = $eventLogReadersSid
    service_identity_member = $null
    failure_reason = $null
}
if ($splunkService) {
    $splunkEventLogAccess.attempted = $true
    $serviceIdentity = $splunkEventLogAccess.service_identity
    if ([string]::IsNullOrWhiteSpace($serviceIdentity)) {
        $splunkEventLogAccess.failure_reason = 'service_identity_unavailable'
        $script:Errors.Add('splunk.event_log_access: SplunkForwarder service identity is unavailable')
    } else {
        try {
            $serviceAccount = [System.Security.Principal.NTAccount]::new([string]$serviceIdentity)
            $serviceSid = $serviceAccount.Translate([System.Security.Principal.SecurityIdentifier])
            $splunkEventLogAccess.service_identity_sid = $serviceSid.Value
        } catch {
            $splunkEventLogAccess.failure_reason = 'service_identity_sid_resolution_failed'
            Add-CheckError -Check 'splunk.event_log_access.service_identity_sid' -Record $_
        }

        if ($splunkEventLogAccess.service_identity_sid) {
            try {
                $groupSid = [System.Security.Principal.SecurityIdentifier]::new($eventLogReadersSid)
                $eventLogReadersGroup = Get-LocalGroup -SID $groupSid -ErrorAction Stop
                if ($null -eq $eventLogReadersGroup) { throw 'Event Log Readers group lookup returned no result.' }
                $groupMembers = @(Get-LocalGroupMember -SID $groupSid -ErrorAction Stop)
                $splunkEventLogAccess.service_identity_member = [bool]($groupMembers | Where-Object {
                    $memberSid = Get-PropertyValue $_ 'SID'
                    $null -ne $memberSid -and [string]$memberSid -eq $splunkEventLogAccess.service_identity_sid
                } | Select-Object -First 1)
            } catch {
                $splunkEventLogAccess.failure_reason = 'event_log_readers_lookup_failed'
                Add-CheckError -Check 'splunk.event_log_access.event_log_readers' -Record $_
            }
        }
    }
}
$splunkExe = if ($splunkService) { Get-ExecutablePathFromCommandLine $splunkService.PathName } else { $null }
$splunkHome = if ($splunkExe) { Split-Path (Split-Path $splunkExe -Parent) -Parent } else { $null }
$splunkMsi = @(Invoke-InventoryCheck 'splunk.msi_metadata' {
    $roots = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
    @(Get-ItemProperty $roots -ErrorAction SilentlyContinue | Where-Object { (Get-PropertyValue $_ 'DisplayName') -match '(?i)Splunk.*Universal Forwarder' } | ForEach-Object {
        $registryPath = Get-PropertyValue $_ 'PSPath'
        [ordered]@{
            display_name = Get-PropertyValue $_ 'DisplayName'; display_version = Get-PropertyValue $_ 'DisplayVersion'
            publisher = Get-PropertyValue $_ 'Publisher'; product_code = Get-PropertyValue $_ 'PSChildName'
            install_location = Get-PropertyValue $_ 'InstallLocation'
            architecture_registry_view = if ($registryPath -match 'WOW6432Node') { 'x86' } elseif ($registryPath) { 'x64' } else { $null }
        }
    })
} @())
if (-not $splunkHome -and $splunkMsi.Count -gt 0 -and $splunkMsi[0].install_location) { $splunkHome = $splunkMsi[0].install_location.TrimEnd('\') }
$splunkVersion = $null
$splunkExecutableEvidence = $null
$btool = $null
$btoolArtifacts = [System.Collections.Generic.List[object]]::new()
$btoolAttempts = [System.Collections.Generic.List[object]]::new()
$btoolCollectionStatus = 'unavailable'
$btoolUnavailableReason = if ($splunkHome) { 'btool_executable_not_found' } else { 'splunk_home_not_discovered' }
$btoolFailureCount = 0
$effectiveSysmonInput = @()
$effectiveForwarding = @()
if ($splunkHome) {
    $splunkCommand = Join-Path $splunkHome 'bin\splunk.exe'
    $btool = Join-Path $splunkHome 'bin\btool.exe'
    if (Test-Path -LiteralPath $splunkCommand -PathType Leaf) {
        $splunkExecutableEvidence = Invoke-InventoryCheck 'splunk.executable_evidence' { Get-FileEvidence $splunkCommand }
        $versionResult = Invoke-InventoryCheck 'splunk.version' { Invoke-ReadOnlyProcess $splunkCommand 'version' }
        if ($versionResult) { $splunkVersion = ($versionResult.stdout + $versionResult.stderr).Trim() }
    }
    if (Test-Path -LiteralPath $btool -PathType Leaf) {
        $btoolCollectionStatus = 'success'
        $btoolUnavailableReason = $null
        foreach ($configuration in @('inputs', 'outputs', 'deploymentclient', 'server')) {
            $result = Invoke-InventoryCheck ("splunk.btool.{0}" -f $configuration) { Invoke-ReadOnlyProcess $btool ("{0} list --debug" -f $configuration) @{ SPLUNK_HOME = $splunkHome } }
            $btoolEnvironmentError = $result -and (($result.stdout + [Environment]::NewLine + $result.stderr) -match '(?im)^\s*SPLUNK_HOME must be set\.\s+Stopping\.\s*$')
            if ($result -and $result.exit_code -eq 0 -and -not [string]::IsNullOrWhiteSpace($result.stdout) -and -not $btoolEnvironmentError) {
                $sanitized = Protect-SplunkText ($result.stdout + [Environment]::NewLine + $result.stderr)
                $fileName = "splunk-btool-{0}-sanitized.txt" -f $configuration
                Set-Content -LiteralPath (Join-Path $outputDirectory $fileName) -Value $sanitized -Encoding UTF8
                $btoolArtifacts.Add([ordered]@{ configuration = $configuration; file = $fileName; exit_code = $result.exit_code; sanitized = $true })
                $btoolAttempts.Add([ordered]@{ configuration = $configuration; status = 'success'; exit_code = $result.exit_code; artifact = $fileName })
                if ($configuration -eq 'inputs') { $effectiveSysmonInput = Get-BtoolStanza $sanitized '(?i)^WinEventLog://Microsoft-Windows-Sysmon/Operational$' }
                if ($configuration -eq 'outputs') { $effectiveForwarding = Get-BtoolStanza $sanitized '(?i)^(tcpout|tcpout:.*)$' }
            } elseif ($result -and $result.exit_code -eq 0 -and [string]::IsNullOrWhiteSpace($result.stdout) -and -not $btoolEnvironmentError) {
                $btoolAttempts.Add([ordered]@{ configuration = $configuration; status = 'not_configured'; exit_code = $result.exit_code; artifact = $null; reason = 'no_effective_configuration' })
            } else {
                $btoolFailureCount++
                $btoolCollectionStatus = 'partial_failure'
                $reason = if (-not $result) { 'invocation_failed' } elseif ($result.exit_code -ne 0) { 'nonzero_exit' } elseif ($btoolEnvironmentError) { 'splunk_home_not_seen_by_child' } else { 'no_usable_stdout' }
                $exitCode = if ($result) { $result.exit_code } else { $null }
                $btoolAttempts.Add([ordered]@{ configuration = $configuration; status = 'failed'; exit_code = $exitCode; artifact = $null; reason = $reason })
                $script:Errors.Add(("splunk.btool.{0}: collection failed ({1}, exit code {2}); no artifact was created" -f $configuration, $reason, $exitCode))
            }
        }
        if ($btoolFailureCount -eq 4) { $btoolCollectionStatus = 'failed' }
    }
}
$splunkConfigHashes = Invoke-InventoryCheck 'splunk.config_hashes' {
    if (-not $splunkHome) { return @() }
    $allowedNames = @('inputs.conf', 'outputs.conf', 'deploymentclient.conf', 'server.conf')
    @(Get-ChildItem -LiteralPath (Join-Path $splunkHome 'etc') -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $allowedNames -contains $_.Name } | ForEach-Object {
        [ordered]@{ relative_path = $_.FullName.Substring($splunkHome.TrimEnd('\').Length).TrimStart('\'); sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
    })
} @()

$inventory = [ordered]@{
    schema = 'alert2ir.windows-endpoint-inventory'; schema_version = 1
    collected_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    collector = [ordered]@{ name = 'Collect-Alert2IREndpointInventory.ps1'; version = '1.0.0'; elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
    system = [ordered]@{
        computer_name = $env:COMPUTERNAME
        membership = if ($computerSystem) { [ordered]@{ part_of_domain = $computerSystem.PartOfDomain; domain_or_workgroup = $computerSystem.Domain } } else { $null }
        os_architecture = if ($operatingSystem) { $operatingSystem.OSArchitecture } else { $env:PROCESSOR_ARCHITECTURE }
        registry_version = $osRegistry
        actual_os_version = if ($operatingSystem) { [ordered]@{ version = $operatingSystem.Version; build_number = $operatingSystem.BuildNumber; caption = $operatingSystem.Caption } } else { [Environment]::OSVersion.Version.ToString() }
        powershell_version = $PSVersionTable.PSVersion.ToString(); timezone = [TimeZoneInfo]::Local.Id
        windows_time = $timeService
        last_boot_time_utc = if ($operatingSystem) { Convert-CimDate $operatingSystem.LastBootUpTime } else { $null }
        virtualbox_guest_additions = $guestAdditions; puppet = $puppet
    }
    network = [ordered]@{
        active_adapters = $networkAdapters; ip_configuration = $ipConfigurations; connection_profiles = $connectionProfiles
        firewall_profiles = $firewallProfiles; name_resolution = @($nameResolution); splunk_tcp_test = $tcpTest
        route_to_splunk = $route; tcp_connections_remote_port_9997 = $tcpConnections
    }
    sysmon = [ordered]@{
        optional_feature = $sysmonFeature; services_and_drivers = @($sysmonServices); file_evidence = @($sysmonFiles)
        implementation_evidence = [ordered]@{
            classification = $sysmonImplementation; feature_state = $sysmonFeature.state
            file_product_and_company_fields = 'See file_evidence'
            interpretation = 'Built-in Sysmon is indicated by the enabled Windows optional feature; standalone Sysinternals Sysmon is a candidate when service/file evidence exists without that enabled feature.'
        }
        read_only_inspection = $sysmonInspection; operational_log = $sysmonLog
    }
    splunk_universal_forwarder = [ordered]@{
        installed = [bool]($splunkService -or $splunkHome); splunk_home = $splunkHome
        product = [ordered]@{
            version_command_output = $splunkVersion; executable_evidence = $splunkExecutableEvidence
            architecture = if ($splunkMsi.Count -gt 0) { $splunkMsi[0].architecture_registry_view } else { $null }
            msi_metadata = @($splunkMsi)
        }
        service = if ($splunkService) { [ordered]@{ state = $splunkService.State; start_mode = $splunkService.StartMode; account = $splunkService.StartName; image_path = $splunkService.PathName } } else { $null }
        event_log_access = $splunkEventLogAccess
        btool_collection = [ordered]@{ status = $btoolCollectionStatus; unavailable_reason = $btoolUnavailableReason; attempts = @($btoolAttempts) }
        btool_artifacts = @($btoolArtifacts); effective_sysmon_operational_input = @($effectiveSysmonInput)
        effective_forwarding_destinations_and_groups = @($effectiveForwarding); configuration_file_hashes = @($splunkConfigHashes)
    }
    diagnostics = [ordered]@{ warnings = @($script:Warnings); errors = @($script:Errors) }
}

$jsonPath = Join-Path $outputDirectory 'endpoint-inventory.json'
$inventory | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
Write-Output $outputDirectory
