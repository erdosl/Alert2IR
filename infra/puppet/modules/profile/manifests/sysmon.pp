class profile::sysmon {
  file { 'C:/ProgramData/Alert2IR':
    ensure => directory,
  }

  file { 'C:/ProgramData/Alert2IR/Sysmon':
    ensure  => directory,
    require => File['C:/ProgramData/Alert2IR'],
  }

  file { 'C:/ProgramData/Alert2IR/Sysmon/alert2ir-sysmon.xml':
    ensure  => file,
    source  => 'puppet:///modules/profile/sysmon/alert2ir-sysmon.xml',
    require => File['C:/ProgramData/Alert2IR/Sysmon'],
  }

  service { 'Sysmon64':
    ensure => running,
    enable => true,
  }
}
