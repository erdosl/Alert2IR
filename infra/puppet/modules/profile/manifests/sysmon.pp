class profile::sysmon {
  service { 'Sysmon64':
    ensure => running,
    enable => true,
  }
}
