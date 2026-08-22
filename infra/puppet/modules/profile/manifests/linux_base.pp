class profile::linux_base {
  $kernel = $facts['kernel']
  if !($kernel =~ String[1]) {
    fail('Cannot determine a usable kernel fact for the Alert2IR Linux baseline')
  }
  if $kernel != 'Linux' {
    fail("Unsupported kernel '${kernel}'; Alert2IR Linux roles require Linux")
  }

  $os = $facts['os']
  if !($os =~ Hash) {
    fail('Cannot determine usable structured OS facts for the Alert2IR Linux baseline')
  }

  $os_name = $os['name']
  if !($os_name =~ String[1]) {
    fail('Cannot determine a usable OS name for the Alert2IR Linux baseline')
  }
  if $os_name != 'Ubuntu' {
    fail("Unsupported OS '${os_name}'; Alert2IR Linux roles require Ubuntu")
  }

  $os_release = $os['release']
  if !($os_release =~ Hash) {
    fail('Cannot determine usable structured OS release facts for the Alert2IR Linux baseline')
  }

  $os_release_major = $os_release['major']
  if !($os_release_major =~ String[1]) {
    fail('Cannot determine a usable OS major release for the Alert2IR Linux baseline')
  }
  if $os_release_major != '24.04' {
    fail("Unsupported Ubuntu release '${os_release_major}'; Alert2IR Linux roles require 24.04")
  }

  $architecture = $os['architecture']
  if !($architecture =~ String[1]) {
    fail('Cannot determine a usable OS architecture for the Alert2IR Linux baseline')
  }
  if !($architecture in ['amd64', 'x86_64']) {
    fail("Unsupported architecture '${architecture}'; Alert2IR Linux roles require amd64")
  }
}
