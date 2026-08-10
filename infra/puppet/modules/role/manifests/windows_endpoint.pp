class role::windows_endpoint {
  contain profile::base
  contain profile::sysmon
  contain profile::splunk_forwarder
}
