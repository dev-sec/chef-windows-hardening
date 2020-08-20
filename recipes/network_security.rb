#
# Cookbook Name:: windows-hardening
# Recipe:: network_security
#
# Copyright (c) 2019 Patrick Muench, All Rights Reserved.

return unless node['platform_family'] == 'windows'

# Ensure \'Network security: Allow LocalSystem NULL session fallback\' is set to \'Disabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.2'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.2'
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0' do
  values [{
    name: 'AllowNullSessionFallback',
    type: :dword,
    data: 0
  }]
  action :create
  recursive true
end

# Ensure \'Network Security: Allow PKU2U authentication requests to this computer to use online identities\' is set to \'Disabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.3'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.3'
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\pku2u' do
  values [{
    name: 'AllowOnlineID',
    type: :dword,
    data: 0
  }]
  action :create
  recursive true
end

# Ensure \'Network security: Configure encryption types allowed for Kerberos\' is set to \'RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.4'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.4'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters' do
  values [{
    name: 'SupportedEncryptionTypes',
    type: :dword,
    data: 2_147_483_644
  }]
  action :create
  recursive true
end

# Ensure \'Network security: Do not store LAN Manager hash value on next password change\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.5'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.5'
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa' do
  values [{
    name: 'NoLMHash',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Network security: Force logoff when logon hours expire\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.6'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.6'
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters' do
  values [{
    name: 'EnableForcedLogOff',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Network security: LAN Manager authentication level\' is set to \'Send NTLMv2 response only. Refuse LM\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.7'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.7'
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa' do
  values [{
    name: 'LmCompatibilityLevel',
    type: :dword,
    data: 5
  }]
  action :create
  recursive true
end

# Ensure \'Network security: LDAP client signing requirements\' is set to \'Negotiate signing\' or higher\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.8'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.8'
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LDAP' do
  values [{
    name: 'LDAPClientIntegrity',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

# Ensure \'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients\' is set to \'Require NTLMv2 session security, Require 128-bit encryption\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.9'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.9'
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0' do
  values [{
    name: 'NTLMMinClientSec',
    type: :dword,
    data: 536_870_912
  }]
  action :create
  recursive true
end

# Ensure \'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers\' is set to \'Require NTLMv2 session security, Require 128-bit encryption\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.11.10'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.11.10'
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0' do
  values [{
    name: 'NTLMMinServerSec',
    type: :dword,
    data: 536_870_912
  }]
  action :create
  recursive true
end
