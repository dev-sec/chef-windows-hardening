# General security policy settings
default['security_policy']['template']['location'] = 'C:\Windows\security\templates'
default['security_policy']['database']['location'] = 'C:\Windows\security\database'
default['security_policy']['database']['name'] = 'hardening.sdb'

# System access settings
# Nil value means nothing will be written to the security policy template.
default['security_policy']['access']['PasswordComplexity'] = 1
default['security_policy']['access']['LockoutBadCount'] = 3
default['security_policy']['access']['ResetLockoutCount'] = 15
default['security_policy']['access']['LockoutDuration'] = 15

# Security policy rights / privileges settings.
default['security_policy']['rights']['SeRemoteInteractiveLogonRight']       = '*S-1-5-32-544'
default['security_policy']['rights']['SeTcbPrivilege']                      = '*S-1-0-0'
default['security_policy']['rights']['SeMachineAccountPrivilege']           = '*S-1-5-32-544'
default['security_policy']['rights']['SeTrustedCredManAccessPrivilege']     = '*S-1-0-0'
default['security_policy']['rights']['SeNetworkLogonRight']                 = '*S-1-0-0'
