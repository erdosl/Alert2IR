class profile::docker_host(
  Optional[String[1]] $daemon_config_source = undef,
) {
  if $daemon_config_source != undef and $daemon_config_source != 'obs01-daemon.json' {
    fail("Unsupported Alert2IR Docker daemon configuration source '${daemon_config_source}'")
  }

  package { 'ca-certificates':
    ensure => installed,
  }

  file { '/etc/apt/keyrings':
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  file { '/etc/apt/keyrings/docker.asc':
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    source  => 'puppet:///modules/profile/docker/docker.asc',
    require => [Package['ca-certificates'], File['/etc/apt/keyrings']],
    notify  => Exec['alert2ir-docker-apt-update'],
  }

  file { '/etc/apt/sources.list.d/docker.sources':
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    source  => 'puppet:///modules/profile/docker/docker.sources',
    require => File['/etc/apt/keyrings/docker.asc'],
    notify  => Exec['alert2ir-docker-apt-update'],
  }

  file { '/etc/apt/preferences.d/alert2ir-docker':
    ensure => file,
    owner  => 'root',
    group  => 'root',
    mode   => '0644',
    source => 'puppet:///modules/profile/docker/apt-preferences',
  }

  exec { 'alert2ir-docker-apt-update':
    command     => '/usr/bin/apt-get update -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/docker.sources -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0',
    refreshonly => true,
  }

  package { 'containerd.io':
    ensure  => '2.3.3-1~ubuntu.24.04~noble',
    require => [Exec['alert2ir-docker-apt-update'], File['/etc/apt/preferences.d/alert2ir-docker']],
  }

  package { 'docker-ce':
    ensure  => '5:29.7.2-1~ubuntu.24.04~noble',
    require => [Exec['alert2ir-docker-apt-update'], File['/etc/apt/preferences.d/alert2ir-docker']],
  }

  package { 'docker-ce-cli':
    ensure  => '5:29.7.2-1~ubuntu.24.04~noble',
    require => [Exec['alert2ir-docker-apt-update'], File['/etc/apt/preferences.d/alert2ir-docker']],
  }

  package { 'docker-buildx-plugin':
    ensure  => '0.36.1-1~ubuntu.24.04~noble',
    require => [Exec['alert2ir-docker-apt-update'], File['/etc/apt/preferences.d/alert2ir-docker']],
  }

  package { 'docker-compose-plugin':
    ensure  => '5.4.0-1~ubuntu.24.04~noble',
    require => [Exec['alert2ir-docker-apt-update'], File['/etc/apt/preferences.d/alert2ir-docker']],
  }

  file { '/etc/containerd/config.toml':
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    source  => 'puppet:///modules/profile/docker/containerd-config.toml',
    require => Package['containerd.io'],
  }

  file { '/etc/docker':
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  if $daemon_config_source == undef {
    file { '/etc/docker/daemon.json':
      ensure  => absent,
      require => File['/etc/docker'],
      before  => Package['docker-ce'],
    }
  } else {
    file { '/etc/docker/daemon.json':
      ensure  => file,
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      source  => "puppet:///modules/profile/docker/${daemon_config_source}",
      require => File['/etc/docker'],
      before  => Package['docker-ce'],
    }
  }

  service { 'containerd':
    ensure  => running,
    enable  => true,
    require => [Package['containerd.io'], File['/etc/containerd/config.toml']],
  }

  service { 'docker':
    ensure  => running,
    enable  => true,
    require => [Package['docker-ce'], Package['docker-ce-cli'], Service['containerd']],
  }
}
