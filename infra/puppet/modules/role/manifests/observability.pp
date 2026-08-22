class role::observability {
  contain profile::linux_base
  contain profile::host_identity_guard
  contain profile::operator_tools
}
