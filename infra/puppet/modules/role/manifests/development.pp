class role::development {
  contain profile::linux_base
  contain profile::host_identity_guard
  contain profile::operator_tools
  contain profile::docker_host
  contain profile::development
}
