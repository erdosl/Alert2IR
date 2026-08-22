class profile::host_identity_guard(
  String[1] $expected_host_only_ipv4,
) {
  if !($trusted =~ Hash) {
    fail('Cannot determine usable trusted facts for Alert2IR host identity verification')
  }

  $certname = $trusted['certname']
  if !($certname =~ String[1]) {
    fail('Cannot determine a usable trusted certname for Alert2IR host identity verification')
  }
  if $certname !~ /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/ {
    fail("Trusted certname '${certname}' is not a usable Alert2IR short hostname")
  }

  $networking = $facts['networking']
  if !($networking =~ Hash) {
    fail('Cannot determine usable structured networking facts for Alert2IR host identity verification')
  }

  $hostname = $networking['hostname']
  if !($hostname =~ String[1]) {
    fail('Cannot determine a usable networking hostname for Alert2IR host identity verification')
  }
  if $hostname !~ /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/ {
    fail("Networking hostname '${hostname}' is not a usable Alert2IR short hostname")
  }
  if $certname != $hostname {
    fail("Trusted certname '${certname}' does not match networking hostname '${hostname}'")
  }

  $interfaces = $networking['interfaces']
  if !($interfaces =~ Hash) {
    fail('Cannot determine traversable network interface facts for Alert2IR host identity verification')
  }
  if $interfaces.empty {
    fail('Cannot determine traversable network interface facts for Alert2IR host identity verification')
  }

  $matching_interfaces = $interfaces.filter |$interface_name, $interface_facts| {
    if !($interface_facts =~ Hash) {
      fail("Network interface '${interface_name}' has unusable structured facts")
    }

    $bindings = $interface_facts['bindings']
    if !($bindings =~ Array) {
      fail("Network interface '${interface_name}' has no traversable IPv4 bindings")
    }

    $matching_bindings = $bindings.filter |$binding| {
      if !($binding =~ Hash) {
        fail("Network interface '${interface_name}' has an unusable IPv4 binding")
      }

      $address = $binding['address']
      if !($address =~ String[1]) {
        fail("Network interface '${interface_name}' has an IPv4 binding without a usable address")
      }

      $address == $expected_host_only_ipv4
    }

    if $matching_bindings.length > 1 {
      fail("Expected host-only IPv4 '${expected_host_only_ipv4}' appears more than once on interface '${interface_name}'")
    }

    $matching_bindings.length == 1
  }

  if $matching_interfaces.empty {
    fail("Expected host-only IPv4 '${expected_host_only_ipv4}' is absent from network interface bindings")
  }
  if $matching_interfaces.length > 1 {
    fail("Expected host-only IPv4 '${expected_host_only_ipv4}' appears on more than one network interface")
  }
}
