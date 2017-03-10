#
# Cookbook Name:: base-win2012-hardening
# Recipe:: default
#
# Copyright (c) 2016 Joe Gardiner, All Rights Reserved.

include_recipe 'windows-hardening::01_password_policy'
include_recipe 'windows-hardening::02_account_lockout'
include_recipe 'windows-hardening::03_user_rights'
include_recipe 'windows-hardening::04_audit'
include_recipe 'windows-hardening::05_ie'
include_recipe 'windows-hardening::07_rdp'
include_recipe 'windows-hardening::08_access'
