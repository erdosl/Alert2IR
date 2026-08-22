class profile::operator_tools {
  package { 'ripgrep':
    ensure => installed,
  }

  package { 'shellcheck':
    ensure => installed,
  }
}
