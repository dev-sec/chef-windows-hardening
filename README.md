# base-win2012-hardening
This cookbook provides recipes for ensuring that a Windows 2012 R2 system is compliant with the Base Windows 2012 R2 Chef Compliance profile.

## Coding guidelines
Use Chef resources wherever possible. Lock files have been used for secedit.exe and auditpol commands. The registry_key resource has been used extensively.

## Testing the cookbook
As the results of the cookbook need to be verified by running a Compliance scan against them it is recommended to use an EC2 instance in a Chef environment, made up of a Chef Server and a Compliance Server. The following command can be used for bootstrapping a node.

### Bootstrap a test node
`knife ec2 server create --node-name windows-test --flavor t2.medium --image ami-29eb7e5a --security-group-ids sg-238e5744 --user-data win-userdata.ps1 --winrm-user Administrator --winrm-password Ch4ng3m3 --ssh-key emea-sa-shared -r 'recipe[base-win2012-hardening::enable_winrm_access]'`

**Please note the following:**
* To bootstrap a Windows node using Knife you need a predictable password. The `win-userdata.ps1` file, in this repo, provides this.
* You need a security group that allows winrm access and RDP access.
* We set a run-list. The `enable_winrm_access` recipe prepares the node for a manual Compliance scan.

## Applying at scale
This cookbook is currently only for testing purposes, or to demonstrate the Asses & Remediate workflow, for Windows.If you wish to apply this at scale, use a role and add the cookbook to its runlist, there is no need to apply a specific recipe.

## Pre-requisites
gem install kitchen-inspec

## Contributors + Kudos

* Dominik Richter [arlimus](https://github.com/arlimus)
* Christoph Hartmann [chris-rock](https://github.com/chris-rock)
* Simon Fisher [simfish85](https://github.com/simfish85)
* Alex Pop [alexpop](https://github.com/alexpop)
* Yvo Van Doorn [yvovandoorn](https://github.com/yvovandoorn)
* Matthew Tunny [MattTunny](https://github.com/matttunny)


## Contributing

See [contributor guideline](CONTRIBUTING.md).


## License and Author

* Author:: Joe Gardiner <joe@grdnr.io> <joe@chef.io>
* Author:: Chef Software Ltd

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
