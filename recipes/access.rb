#
# Cookbook Name:: windows-hardening
# Recipe:: access
#
# Copyright (c) 2019 Patrick Muench, All Rights Reserved.
# Copyright (c) 2016 Joe Gardiner, All Rights Reserved.

return unless node['platform_family'] == 'windows'

# Anonymous Access to Windows Shares and Named Pipes is Disallowed
# windows-baseline: windows-base-102

if node['windows_hardening']['smbv1']['disable'] == true
  registry_key 'HKLM\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters' do
    values [{
      name: 'SMB1',
      type: :dword,
      data: 0
    }]
    action :create_if_missing
  end
end
