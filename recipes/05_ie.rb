#
# Cookbook Name:: base-win2012-hardening
# Recipe:: ie
#
# Copyright (c) 2016 Joe Gardiner, All Rights Reserved.

# start of fix for windows-ie-101 - IE 64-bit tab
registry_key 'HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Main' do
  values [{
    name: 'Isolation64Bit',
    type: :dword,
    data: 1
  }]
  recursive true
  action :create
end
# end of fix for windows-ie-101 - IE 64-bit tab

# start of fix for windows-ie-102 - Run antimalware programs against ActiveX controls
registry_key 'HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3' do
  values [{
    name: '270C',
    type: :dword,
    data: 0
  }]
  recursive true
  action :create
end
# end of fix for windows-ie-102 - Run antimalware programs against ActiveX controls
