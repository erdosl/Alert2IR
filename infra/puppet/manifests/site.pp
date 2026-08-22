node 'win11-01', 'win11-02' {
  include role::windows_endpoint
}

node 'splunk' {
  include role::splunk_server
}

node 'ir-core' {
  include role::ir_core
}

node 'dev01' {
  include role::development
}

node 'obs01' {
  include role::observability
}

node default {
  fail('Refusing to compile an unclassified Alert2IR node')
}
