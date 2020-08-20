#
# Cookbook Name:: windows-hardening
# Recipe:: shutdown
#
# Copyright (c) 2019 Patrick Muench, All Rights Reserved.

return unless node['platform_family'] == 'windows'

# Ensure \'Shutdown: Allow system to be shut down without having to log on\' is set to \'Disabled\'
# tag 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0 - 03-30-2018': '2.3.13.1'
# tag 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.1.0 - 10-31-2018': '2.3.13.1'
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{
    name: 'ShutdownWithoutLogon',
    type: :dword,
    data: 0
  }]
  action :create
  recursive true
end
