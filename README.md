# windows-hardening (Chef Cookbook)

This cookbook provides recipes for ensuring that a Windows 2012 R2 system is compliant with the [DevSec Windows Baseline](https://github.com/dev-sec/windows-baseline).

### Platforms

- Windows Server 2012
- Windows Server 2012 R2
- Windows Server 2016
- Windows Server 2016 Nano Server

## Coding guidelines

Use Chef resources wherever possible. Some Chef resources we use to manage Windows:

- [registry_key](https://docs.chef.io/windows.html#registry-key)
- [powershell_script](https://docs.chef.io/windows.html#powershell-script)
- [security_policy](https://github.com/grdnrio/windows-security-policy)

If no Chef resource is available, we prefer to use Powershell or Powershell DSC.

## Testing the cookbook

### Test-Kitchen

This cookbooks ships with a test-kitchen setup to verify that the implementation follows the [DevSec Windows Baseline](https://github.com/dev-sec/windows-baseline):

```
kitchen test
```

### Chef Server and Chef Compliance

If you use Chef Server, you can bootstrap a node and run a Chef Compliance against them it. It is recommended to use an EC2 instance in a Chef environment, made up of a Chef Server and a Compliance Server. The following command can be used for bootstrapping a node.

```
knife ec2 server create --node-name windows-test --flavor t2.medium --image ami-29eb7e5a --security-group-ids sg-238e5744 --user-data win-userdata.ps1 --winrm-user Administrator --winrm-password Ch4ng3m3 --ssh-key emea-sa-shared -r 'recipe[base-win2012-hardening::enable_winrm_access]'
```

**Please note the following:**
* To bootstrap a Windows node using Knife you need a predictable password. The `win-userdata.ps1` file, in this repo, provides this.
* You need a security group that allows winrm access and RDP access.
* We set a run-list. The `enable_winrm_access` recipe prepares the node for a manual Compliance scan.

## Applying at scale
This cookbook is currently in development. It does not cover all requirements to provide a fully hardened Windows environment yet. Any contributions are welcome to improve the cookbook. If you wish to apply this at scale, use a role and add the cookbook to its runlist, there is no need to apply a specific recipe.

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
* Author:: Christoph Hartmann <chris@lollyrock.com> <chris@lollyrock.com>
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
