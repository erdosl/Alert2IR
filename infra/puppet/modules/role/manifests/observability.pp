class role::observability {
  contain profile::linux_base
  contain profile::host_identity_guard
  contain profile::operator_tools
  contain profile::docker_host
  contain profile::observability_host
  contain profile::alloy

  Class['profile::docker_host'] -> Class['profile::alloy']
  Class['profile::observability_host'] -> Class['profile::alloy']
}
