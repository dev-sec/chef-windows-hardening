#
# Cookbook Name:: windows-hardening
# Recipe:: ie
#
# Copyright (c) 2016 Joe Gardiner, All Rights Reserved.

return unless node['platform_family'] == 'windows'

# IE 64-bit tab
# windows-baseline: windows-ie-101
registry_key 'HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Main' do
  values [{
    name: 'Isolation64Bit',
    type: :dword,
    data: 1
  }]
  recursive true
  action :create
end

# Run antimalware programs against ActiveX controls
# windows-baseline: windows-ie-102
registry_key 'HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
  values [{
    name: '270C',
    type: :dword,
    data: 0
  }]
  recursive true
  action :create
end
