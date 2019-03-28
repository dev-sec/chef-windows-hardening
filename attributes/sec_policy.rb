# encoding: utf-8

# Cookbook Name:: windows-hardening
# Attributes:: security_policy

# General security policy settings
default['security_policy']['template']['location'] = 'C:\Windows\security\templates'
default['security_policy']['database']['location'] = 'C:\Windows\security\database'
default['security_policy']['database']['name'] = 'hardening.sdb'

# System access settings
# Nil value means nothing will be written to the security policy template.

# Ensure \'Enforce password history\' is set to \'24 or more password(s)\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '1.1.1'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '1.1.1'
default['security_policy']['access']['PasswordHistorySize'] = 24

# Ensure \'Maximum password age\' is set to \'60 or fewer days, but not 0\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '1.1.2'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '1.1.2'
default['security_policy']['access']['MaximumPasswordAge'] = 60

# Ensure \'Minimum password age\' is set to \'1 or more day(s)\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '1.1.3'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '1.1.3'
default['security_policy']['access']['MinimumPasswordAge'] = 1

# Ensure \'Minimum password length\' is set to \'14 or more character(s)\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '1.1.4'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '1.1.4'
default['security_policy']['access']['MinimumPasswordLength'] = 14

# Ensure \'Password must meet complexity requirements\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '1.1.5'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '1.1.5'
default['security_policy']['access']['PasswordComplexity'] = 1

# Ensure \'Store passwords using reversible encryption\' is set to \'Disabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '1.1.6'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '1.1.6'
default['security_policy']['access']['ClearTextPassword'] = 0

# Ensure \'Account lockout duration\' is set to \'15 or more minute(s)\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '1.2.1'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '1.2.1'
default['security_policy']['access']['LockoutDuration'] = 15

# Ensure \'Account lockout threshold\' is set to \'10 or fewer invalid logon attempt(s), but not 0\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '1.2.2'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '1.2.2'
default['security_policy']['access']['LockoutBadCount'] = 10

# Ensure \'Reset account lockout counter after\' is set to \'15 or more minute(s)\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '1.2.3'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '1.2.3'
default['security_policy']['access']['ResetLockoutCount'] = 15

# Ensure \'Access Credential Manager as a trusted caller\' is set to \'No One\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.1'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.1'
default['security_policy']['rights']['SeTrustedCredManAccessPrivilege'] = ''

# Configure \'Access this computer from the network\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.2'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': ['2.2.2', '2.2.3']
default['security_policy']['rights']['SeNetworkLogonRight'] = ''

# Ensure \'Act as part of the operating system\' is set to \'No One\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.3'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.4'
default['security_policy']['rights']['SeTcbPrivilege'] = ''

# Ensure \'Add workstations to domain\' is set to \'Administrators\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.4'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.5'
default['security_policy']['rights']['SeMachineAccountPrivilege'] = '*S-1-5-32-544'

# Ensure \'Adjust memory quotas for a process\' is set to \'Administrators, LOCAL SERVICE, NETWORK SERVICE\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.5'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.6'
default['security_policy']['rights']['SeIncreaseQuotaPrivilege'] = '*S-1-5-19, *S-1-5-20, *S-1-5-32-544'

# Ensure \'Allow log on locally\' is set to \'Administrators\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.6'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.7'
default['security_policy']['rights']['SeInteractiveLogonRight'] = '*S-1-5-9, *S-1-5-32-544'

# Configure \'Allow log on through Remote Desktop Services\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.7'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': ['2.2.8', '2.2.9']
default['security_policy']['rights']['SeRemoteInteractiveLogonRight'] = '*S-1-5-32-544'

# Ensure \'Back up files and directories\' is set to \'Administrators\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.8'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.10'
default['security_policy']['rights']['SeBackupPrivilege'] = '*S-1-5-32-544'

# Ensure \'Change the system time\' is set to \'Administrators, LOCAL SERVICE\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.9'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.11'
# Ensure \'Change the time zone\' is set to \'Administrators, LOCAL SERVICE\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.10'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.12'
default['security_policy']['rights']['SeSystemtimePrivilege'] = '*S-1-5-19, *S-1-5-32-544'

# Ensure \'Create a pagefile\' is set to \'Administrators\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.11'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.13'
default['security_policy']['rights']['SeCreatePagefilePrivilege'] = '*S-1-5-32-544'

# Ensure \'Create a token object\' is set to \'No One\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.12'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.14'
default['security_policy']['rights']['SeCreateTokenPrivilege'] = ''

# Ensure \'Create global objects\' is set to \'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.13'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.15'
default['security_policy']['rights']['SeCreateGlobalPrivilege'] = '*S-1-5-19, *S-1-5-20, *S-1-5-32-544, *S-1-5-6'

# Ensure \'Create permanent shared objects\' is set to \'No One\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.14'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.16'
default['security_policy']['rights']['SeCreatePermanentPrivilege'] = ''

# Ensure \'Create symbolic links\' is set to \'Administrators\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.15'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': ['2.2.17', '2.2.18']
default['security_policy']['rights']['SeCreateSymbolicLinkPrivilege'] = '*S-1-5-32-544'

# Ensure \'Debug programs\' is set to \'Administrators\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.16'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.19'
default['security_policy']['rights']['SeDebugPrivilege'] = '*S-1-5-32-544'

# Ensure \'Deny access to this computer from the network\' is set to \'Guests\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.17'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': ['2.2.20', '2.2.21']
default['security_policy']['rights']['SeDenyNetworkLogonRight'] = '*S-1-5-32-546'

# Ensure \'Deny log on as a batch job\' to include \'Guests\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.18'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.22'
default['security_policy']['rights']['SeDenyServiceLogonRight'] = '*S-1-5-32-546'

# Ensure \'Deny log on as a service\' to include \'Guests\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.19'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.23'
default['security_policy']['rights']['SeDenyInteractiveLogonRight'] = '*S-1-5-32-546'

# Ensure \'Deny log on locally\' to include \'Guests\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.20'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.24'
default['security_policy']['rights']['SeMachineAccountPrivilege'] = '*S-1-5-32-546'

# Configure \'Deny log on through Remote Desktop Services\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.21'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': ['2.2.25', '2.2.26']
default['security_policy']['rights']['SeMachineAccountPrivilege'] = '*S-1-5-32-546'

# Configure \'Enable computer and user accounts to be trusted for delegation\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.22'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': ['2.2.27', '2.2.28']
default['security_policy']['rights']['SeEnableDelegationPrivilege'] = ''

# Ensure \'Force shutdown from a remote system\' is set to \'Administrators\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.23'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.29'
default['security_policy']['rights']['SeRemoteShutdownPrivilege'] = '*S-1-5-32-544'

# Ensure \'Generate security audits\' is set to \'LOCAL SERVICE, NETWORK SERVICE\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.24'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.30'
default['security_policy']['rights']['SeAuditPrivilege'] = '*S-1-5-19, *S-1-5-20'

# Configure \'Impersonate a client after authentication\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.25'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': ['2.2.31', '2.2.32']
default['security_policy']['rights']['SeImpersonatePrivilege'] = '*S-1-5-19, *S-1-5-20, *S-1-5-32-544, *S-1-5-6'

# Ensure \'Increase scheduling priority\' is set to \'Administrators\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.26'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.33'
default['security_policy']['rights']['SeIncreaseBasePriorityPrivilege'] = '*S-1-5-32-544'

# Ensure \'Load and unload device drivers\' is set to \'Administrators\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.27'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.34'
default['security_policy']['rights']['SeLoadDriverPrivilege'] = '*S-1-5-32-544'

# Ensure \'Lock pages in memory\' is set to \'No One\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.28'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.35'
default['security_policy']['rights']['SeLockMemoryPrivilege'] = ''

# Ensure \'Log on as a batch job\' is set to \'Administrators\' (DC only)
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.29'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.36'
if ((node['default']['ms_or_dc'] == 'DC') && (node['default']['level_1_or_2'] == 2))
  default['security_policy']['rights']['SeBatchLogonRight'] = '*S-1-5-32-544, *S-1-5-32-551'
end

# Configure \'Manage auditing and security log\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.30'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.38'
default['security_policy']['rights']['SeSecurityPrivilege'] = '*S-1-5-32-544'

# Ensure \'Modify an object label\' is set to \'No One\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.31'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.39'
default['security_policy']['rights']['SeRelabelPrivilege'] = ''

# Ensure \'Modify firmware environment values\' is set to \'Administrators\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.32'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.40'
default['security_policy']['rights']['SeSystemEnvironmentPrivilege'] = '*S-1-5-32-544'

# Ensure \'Perform volume maintenance tasks\' is set to \'Administrators\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.33'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.41'
default['security_policy']['rights']['SeManageVolumePrivilege'] = '*S-1-5-32-544'

# Ensure \'Profile single process\' is set to \'Administrators\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.34'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.42'
default['security_policy']['rights']['SeProfileSingleProcessPrivilege'] = '*S-1-5-32-544'

# Ensure \'Profile system performance\' is set to \'Administrators, NT SERVICE\WdiServiceHost\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.35'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.43'
default['security_policy']['rights']['SeSystemProfilePrivilege'] = '*S-1-5-32-544, *S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420'

# Ensure \'Replace a process level token\' is set to \'LOCAL SERVICE, NETWORK SERVICE\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.36'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.44'
default['security_policy']['rights']['SeAssignPrimaryTokenPrivilege'] = '*S-1-5-19, *S-1-5-20'

# Ensure \'Restore files and directories\' is set to \'Administrators\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.37'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.45'
default['security_policy']['rights']['SeRestorePrivilege'] = '*S-1-5-32-544'

# Ensure \'Shut down the system\' is set to \'Administrators\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.38'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.46'
default['security_policy']['rights']['SeShutdownPrivilege'] = '*S-1-5-32-544'

# Ensure \'Synchronize directory service data\' is set to \'No One\' (DC only)
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.39'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.47'
if node['default']['ms_or_dc'] == 'DC'
  default['security_policy']['rights']['SeSyncAgentPrivilege'] = ''
end

# Ensure \'Take ownership of files or other objects\' is set to \'Administrators\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.2.40'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.2.48'
default['security_policy']['rights']['SeTakeOwnershipPrivilege'] = '*S-1-5-32-544'

#



default['security_policy']['rights']['SeMachineAccountPrivilege'] = '*S-1-5-32-544'
