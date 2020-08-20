# frozen_string_literal: true

#
# Copyright 2019, DevSec Hardening Framework Team
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

name 'windows-hardening'
maintainer 'Joe Gardiner'
maintainer_email 'joe@chef.io'
license 'Apache-2.0'
description 'Hardening cookbook for Windows 2012 R2 and 2016'
long_description 'Remediates critical issues identified by the DevSec Windows baseline'
version '0.9.1'
source_url 'https://github.com/dev-sec/chef-windows-hardening' if respond_to?(:source_url)
issues_url 'https://github.com/dev-sec/chef-windows-hardening/issues' if respond_to?(:issues_url)
chef_version '>= 14'
supports 'windows'
depends 'windows-security-policy'
cookbook 'windows_firewall'
