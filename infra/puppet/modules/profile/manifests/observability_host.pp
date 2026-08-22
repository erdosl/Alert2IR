class profile::observability_host {
  file { '/opt/alert2ir-observability':
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  file { '/opt/alert2ir-observability/releases':
    ensure  => directory,
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
    require => File['/opt/alert2ir-observability'],
  }

  file { '/etc/alert2ir-observability':
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  file { '/etc/alert2ir-observability/secrets':
    ensure  => directory,
    owner   => 'root',
    group   => 'root',
    mode    => '0750',
    require => File['/etc/alert2ir-observability'],
  }

  file { '/srv/alert2ir-observability':
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }
}
