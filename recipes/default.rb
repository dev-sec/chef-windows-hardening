#
# Cookbook Name:: base-win2012-hardening
# Recipe:: default
#
# Copyright (c) 2016 Joe Gardiner, All Rights Reserved.

include_recipe 'base-win2012-hardening::access'
include_recipe 'base-win2012-hardening::ie'
include_recipe 'base-win2012-hardening::rdp'
include_recipe 'base-win2012-hardening::audit-logging'
include_recipe 'base-win2012-hardening::account-lockout'
include_recipe 'base-win2012-hardening::password'
