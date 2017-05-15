# encoding: utf-8
#
# Cookbook Name:: windows-hardening
# Attributes:: default

# set this value if you want to harden terminal services
default['windows_hardening']['rdp']['harden'] = true
default['windows_hardening']['smbv1']['disable'] = true
