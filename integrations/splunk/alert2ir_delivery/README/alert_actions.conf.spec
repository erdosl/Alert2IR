[alert2ir_delivery]
param.adapter_url = Required HTTP(S) URL ending exactly in /v1/splunk/findings.
param.secret_file = Required protected local file containing at least 32 bytes of HMAC secret material.
param.rule_id = Required canonical Sigma UUID from reviewed saved-search configuration.
param.rule_title = Required bounded Sigma title from reviewed saved-search configuration.
param.sigma_level = Required reviewed Sigma level: informational, low, medium, high, or critical.
param.channel = Required Windows event channel; this version accepts Microsoft-Windows-Sysmon/Operational.
