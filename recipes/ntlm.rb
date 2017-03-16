# NTML Hardening
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0' do
  values [{ name: 'NTLMMinServerSec', type: :dword, data: 537_395_200 },
          { name: 'allownullsessionfallback', type: :dword, data: 0 },
          { name: 'NTLMMinClientSec', type: :dword, data: 537_395_200 },
          { name: 'AuditReceivingNTLMTraffic', type: :dword, data: 2 }]
  action :create
end