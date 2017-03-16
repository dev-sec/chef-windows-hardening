#
# Cookbook Name:: windows-hardening
# Recipe:: default
#
# Copyright (c) 2016 Joe Gardiner, All Rights Reserved.

include_recipe 'windows-hardening::password_policy'
include_recipe 'windows-hardening::security_policy'
include_recipe 'windows-hardening::user_rights'
include_recipe 'windows-hardening::audit'
include_recipe 'windows-hardening::ie'
include_recipe 'windows-hardening::rdp'
include_recipe 'windows-hardening::access'
