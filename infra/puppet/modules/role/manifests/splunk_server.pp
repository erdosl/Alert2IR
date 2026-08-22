# This role intentionally does not manage the Splunk server deployment.
class role::splunk_server {
  contain profile::linux_base
  contain profile::host_identity_guard
  contain profile::operator_tools
}
