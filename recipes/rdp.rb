#
# Cookbook Name:: windows-hardening
# Recipe:: rdp
#
# Copyright (c) 2016 Joe Gardiner, All Rights Reserved.

return unless node['platform_family'] == 'windows'

if node['windows_hardening']['rdp']['harden'] == true
  # Windows Remote Desktop Configured to Always Prompt for Password
  # windows-baseline: windows-rdp-100
  registry_key 'HKLM\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services' do
    values [{
      name: 'fPromptForPassword',
      type: :dword,
      data: 1
    }]
    recursive true
    action :create
  end

  # Strong Encryption for Windows Remote Desktop Required
  # windows-baseline: windows-rdp-101
  registry_key 'HKLM\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services' do
    values [{
      name: 'MinEncryptionLevel',
      type: :dword,
      data: 3
    }]
    recursive true
    action :create
  end
end
