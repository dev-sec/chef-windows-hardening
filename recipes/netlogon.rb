# Netlogon Parameters
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters' do
  values [{ name: 'MaximumPasswordAge', type: :dword, data: 30 },
          { name: 'DisablePasswordChange', type: :dword, data: 0 },
          { name: 'RefusePasswordChange', type: :dword, data: 0 },
          { name: 'SealSecureChannel', type: :dword, data: 1 },
          { name: 'RequireSignOrSeal', type: :dword, data: 1 },
          { name: 'SignSecureChannel', type: :dword, data: 1 },
          { name: 'RequireStrongKey', type: :dword, data: 1 },
          { name: 'RestrictNTLMInDomain', type: :dword, data: 7 },
          { name: 'AuditNTLMInDomain', type: :dword, data: 7 }]
  action :create
end