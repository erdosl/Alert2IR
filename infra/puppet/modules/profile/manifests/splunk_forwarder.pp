class profile::splunk_forwarder {
  service { 'SplunkForwarder':
    ensure => running,
    enable => true,
  }
}
