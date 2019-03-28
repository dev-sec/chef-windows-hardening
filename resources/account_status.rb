resource_name :account_status

property :account_status_name, String, name_property: true
property :account_name, String, required: true
property :value, String, required: true

action :set do
  execute new_resource.account_status_name do
    command "net user #{new_resource.account_name} /active:#{new_resource.value}"
    action :run
    not_if { ::File.exist?("C:\\#{new_resource.account_name}_active_#{node['account_status']['active_yes_no']}.lock") }
    notifies :create, "file[C:\\#{new_resource.account_name}_active_#{node['account_status']['active_yes_no']}.lock]", :immediately
  end

  file "C:\\#{new_resource.account_name}_active_#{node['account_status']['active_yes_no']}.lock" do
    action :create
  end
end