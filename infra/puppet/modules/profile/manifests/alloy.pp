class profile::alloy(
  String[1] $config_source,
  String[1] $storage_path,
  String[1] $systemd_dropin_source,
) {
  if $config_source == 'ir-core.alloy' {
    $expected_storage_path = '/var/lib/alloy/alert2ir'
    $expected_systemd_dropin_source = 'ir-core.conf'
    $systemd_dropin_target = '/etc/systemd/system/alloy.service.d/alert2ir.conf'
  } elsif $config_source == 'obs01.alloy' {
    $expected_storage_path = '/srv/alert2ir-observability/alloy'
    $expected_systemd_dropin_source = 'obs01.conf'
    $systemd_dropin_target = '/etc/systemd/system/alloy.service.d/alert2ir-observability.conf'
  } else {
    fail("Unsupported Alert2IR Alloy configuration source '${config_source}'")
  }

  if $storage_path != $expected_storage_path {
    fail("Alloy configuration '${config_source}' requires storage path '${expected_storage_path}'")
  }
  if $systemd_dropin_source != $expected_systemd_dropin_source {
    fail("Alloy configuration '${config_source}' requires systemd drop-in '${expected_systemd_dropin_source}'")
  }

  file { '/etc/apt/keyrings/grafana.asc':
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    source  => 'puppet:///modules/profile/alloy/grafana.asc',
    require => File['/etc/apt/keyrings'],
    notify  => Exec['alert2ir-alloy-apt-update'],
  }

  file { '/etc/apt/sources.list.d/grafana.list':
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    source  => 'puppet:///modules/profile/alloy/grafana.list',
    require => File['/etc/apt/keyrings/grafana.asc'],
    notify  => Exec['alert2ir-alloy-apt-update'],
  }

  file { '/etc/apt/keyrings/grafana.gpg':
    ensure  => absent,
    require => File['/etc/apt/sources.list.d/grafana.list'],
  }

  file { '/etc/apt/preferences.d/alert2ir-alloy':
    ensure => file,
    owner  => 'root',
    group  => 'root',
    mode   => '0644',
    source => 'puppet:///modules/profile/alloy/apt-preferences',
  }

  exec { 'alert2ir-alloy-apt-update':
    command     => '/usr/bin/apt-get update -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/grafana.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0',
    refreshonly => true,
  }

  package { 'alloy':
    ensure  => '1.18.1-1',
    require => [Exec['alert2ir-alloy-apt-update'], File['/etc/apt/preferences.d/alert2ir-alloy']],
  }

  group { 'alloy-containerd':
    ensure => present,
    system => true,
  }

  user { 'alloy':
    ensure     => present,
    groups     => ['docker', 'alloy-containerd'],
    membership => minimum,
    require    => [Package['alloy'], Package['docker-ce'], Group['alloy-containerd']],
    notify     => Exec['alert2ir-alloy-restart'],
  }

  file { '/etc/alloy':
    ensure  => directory,
    owner   => 'root',
    group   => 'alloy',
    mode    => '0750',
    require => Package['alloy'],
  }

  file { $storage_path:
    ensure  => directory,
    owner   => 'alloy',
    group   => 'alloy',
    mode    => '0750',
    require => [Package['alloy'], User['alloy']],
  }

  file { '/etc/alloy/config.alloy':
    ensure       => file,
    owner        => 'root',
    group        => 'alloy',
    mode         => '0640',
    source       => "puppet:///modules/profile/alloy/${config_source}",
    validate_cmd => '/usr/bin/alloy validate %',
    require      => [Package['alloy'], File['/etc/alloy']],
    notify       => Exec['alert2ir-alloy-config-reload'],
  }

  exec { 'alert2ir-alloy-config-reload':
    command     => '/usr/bin/systemctl reload alloy.service',
    onlyif      => '/usr/bin/systemctl is-active --quiet alloy.service',
    refreshonly => true,
  }

  file { '/etc/systemd/system/alloy.service.d':
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  file { $systemd_dropin_target:
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    source  => "puppet:///modules/profile/alloy/systemd/${systemd_dropin_source}",
    require => [File['/etc/systemd/system/alloy.service.d'], File['/etc/alloy/config.alloy'], File[$storage_path]],
    notify  => Exec['alert2ir-alloy-systemd-daemon-reload'],
  }

  exec { 'alert2ir-alloy-systemd-daemon-reload':
    command     => '/usr/bin/systemctl daemon-reload',
    refreshonly => true,
    notify      => Exec['alert2ir-alloy-restart'],
  }

  exec { 'alert2ir-alloy-restart':
    command     => '/usr/bin/systemctl restart alloy.service',
    onlyif      => '/usr/bin/systemctl is-active --quiet alloy.service',
    refreshonly => true,
    require     => [File['/etc/alloy/config.alloy'], File[$systemd_dropin_target], File[$storage_path]],
  }

  file { '/usr/local/sbin/alert2ir-alloy-containerd-access':
    ensure => file,
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
    source => 'puppet:///modules/profile/alloy/alert2ir-alloy-containerd-access.sh',
  }

  file { '/etc/systemd/system/containerd.service.d':
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  file { '/etc/systemd/system/containerd.service.d/20-alert2ir-alloy-containerd-access.conf':
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    source  => 'puppet:///modules/profile/alloy/systemd/20-alert2ir-alloy-containerd-access.conf',
    require => [File['/etc/systemd/system/containerd.service.d'], File['/usr/local/sbin/alert2ir-alloy-containerd-access'], Group['alloy-containerd']],
    notify  => Exec['alert2ir-containerd-systemd-daemon-reload'],
  }

  exec { 'alert2ir-containerd-systemd-daemon-reload':
    command     => '/usr/bin/systemctl daemon-reload',
    refreshonly => true,
  }

  exec { 'alert2ir-alloy-containerd-access':
    command => '/usr/local/sbin/alert2ir-alloy-containerd-access apply',
    unless  => '/usr/local/sbin/alert2ir-alloy-containerd-access check',
    require => [File['/usr/local/sbin/alert2ir-alloy-containerd-access'], Group['alloy-containerd'], Service['containerd']],
  }

  service { 'alloy':
    ensure  => running,
    enable  => true,
    require => [Package['alloy'], User['alloy'], File['/etc/alloy/config.alloy'], File[$systemd_dropin_target], File[$storage_path], Exec['alert2ir-alloy-containerd-access']],
  }

  Exec['alert2ir-alloy-config-reload'] -> Service['alloy']
  Exec['alert2ir-alloy-systemd-daemon-reload'] -> Exec['alert2ir-alloy-restart'] -> Service['alloy']
  Exec['alert2ir-containerd-systemd-daemon-reload'] -> Service['alloy']
}
