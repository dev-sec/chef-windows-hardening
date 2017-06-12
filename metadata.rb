name 'windows-hardening'
maintainer 'Joe Gardiner'
maintainer_email 'joe@chef.io'
license 'Apache 2.0'
description 'Hardening cookbook for Windows 2012 R2'
long_description 'Remediates critical issues identified by the DevSec Windows baseline'
version '0.9.0'
source_url 'https://github.com/dev-sec/chef-windows-hardening' if respond_to?(:source_url)
issues_url 'https://github.com/dev-sec/chef-windows-hardening/issues' if respond_to?(:issues_url)
supports 'windows'
depends 'windows-security-policy'
