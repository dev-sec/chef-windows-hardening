#
# Cookbook Name:: windows-hardening
# Recipe:: domain_controller
#
# Copyright (c) 2019 Patrick Muench, All Rights Reserved.

return unless node['platform_family'] == 'windows' && node['windows_hardening']['ms_or_dc'] == 'DC'

# Ensure \'Domain controller: LDAP server signing requirements\' is set to \'Require signing\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.5.2'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.5.2'
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NTDS\Parameters' do
  values [{
    name: 'LDAPServerIntegrity',
    type: :dword,
    data: 2
  }]
  action :create
  recursive true
end

# Ensure \'Domain controller: Refuse machine account password changes\' is set to \'Disabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.5.3'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.5.3'
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters' do
  values [{
    name: 'RefusePasswordChange',
    type: :dword,
    data: 0
  }]
  action :create
  recursive true
end
