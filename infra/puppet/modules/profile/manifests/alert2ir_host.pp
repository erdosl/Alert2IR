class profile::alert2ir_host {
  file { '/opt/alert2ir':
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  file { '/opt/alert2ir/releases':
    ensure  => directory,
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
    require => File['/opt/alert2ir'],
  }

  file { '/etc/alert2ir':
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  file { '/etc/alert2ir/secrets':
    ensure  => directory,
    owner   => 'root',
    group   => 'root',
    mode    => '0750',
    require => File['/etc/alert2ir'],
  }
}
