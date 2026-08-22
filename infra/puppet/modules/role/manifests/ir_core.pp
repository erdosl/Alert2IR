# This role intentionally does not manage the Alert2IR runtime deployment.
class role::ir_core {
  contain profile::linux_base
  contain profile::host_identity_guard
  contain profile::operator_tools
  contain profile::docker_host
  contain profile::alert2ir_host
  contain profile::alloy

  Class['profile::docker_host'] -> Class['profile::alloy']
}
