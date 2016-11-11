#
# Cookbook Name:: base-win2012-hardening
# Recipe:: access
#
# Copyright (c) 2016 Joe Gardiner, All Rights Reserved.

# start of fix for windows-base-103 - All Shares are Configured
# to Prevent Anonymous Access
registry_key 'HKLM\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters' do
  values [{
    name: 'NullSessionShares',
    type: :multi_string,
    data: ['']
  }]
  action :create_if_missing
end
# end of fix for windows-base-103 - All Shares are Configured
# to Prevent Anonymous Access

# start of fix for windows-base-201 - Strong Windows NTLMv2 Authentication
# Enabled; Weak LM Disabled
registry_key 'HKLM\\System\\CurrentControlSet\\Control\\Lsa' do
  values [{
    name: 'LmCompatibilityLevel',
    type: :dword,
    data: 4
  }]
  action :create
end
# end of fix for windows-base-201 - Strong Windows NTLMv2 Authentication
# Enabled; Weak LM Disabled

# start of fix for windows-base-202 - Enable Strong Encryption for Windows
# Network Sessions on Clients
registry_key 'HKLM\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0' do
  values [{
    name: 'NtlmMinClientSec',
    type: :dword,
    data: 537_395_200
  }]
  action :create
end
# end of fix for windows-base-202 - Enable Strong Encryption for Windows
# Network Sessions on Clients

# start of fix for windows-base-203 - Enable Strong Encryption for Windows
# Network Sessions on Servers
registry_key 'HKLM\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0' do
  values [{
    name: 'NtlmMinServerSec',
    type: :dword,
    data: 537_395_200
  }]
  action :create
end
# end of fix for windows-base-203 - Enable Strong Encryption for Windows
# Network Sessions on Servers
