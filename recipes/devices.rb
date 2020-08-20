#
# Cookbook Name:: windows-hardening
# Recipe:: devices
#
# Copyright (c) 2019 Patrick Muench, All Rights Reserved.

return unless node['platform_family'] == 'windows'

# Ensure \'Devices: Allowed to format and eject removable media\' is set to \'Administrators\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.4.1'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.4.1'
registry_key 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' do
  values [{
    name: 'AllocateDASD',
    type: :dword,
    data: 0
  }]
  action :create
  recursive true
end

# Ensure \'Devices: Prevent users from installing printer drivers\' is set to \'Enabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.4.2'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.4.2'
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' do
  values [{
    name: 'AddPrinterDrivers',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end
