class profile::development {
  package { 'git':
    ensure => installed,
  }
}
