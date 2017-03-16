# LSA settings
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa' do
  values [{ name: 'AuditBaseObjects', type: :dword, data: 1 },
          { name: 'scenoapplylegacyauditpolicy', type: :dword, data: 1 },
          { name: 'DisableDomainCreds', type: :dword, data: 1 },
          { name: 'LimitBlankPasswordUse', type: :dword, data: 1 },
          { name: 'CrashOnAuditFail', type: :dword, data: 0 },
          { name: 'RestrictAnonymousSAM', type: :dword, data: 1 },
          { name: 'RestrictAnonymous', type: :dword, data: 0 },
          { name: 'SubmitControl', type: :dword, data: 0 },
          { name: 'ForceGuest', type: :dword, data: 0 },
          { name: 'EveryoneIncludesAnonymous', type: :dword, data: 0 },
          { name: 'NoLMHash', type: :dword, data: 1 },
          { name: 'LmCompatibilityLevel', type: :dword, data: 5 }]
  action :create
end

# LSA Setting can't be added via registry_key due to hex key bug'
powershell_script 'fullprivilegeauditing' do
  code <<-EOH
Set-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Lsa" -Name fullprivilegeauditing -Value 01
EOH
end
