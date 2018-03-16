resource_name :password_policy

property :policy_name, String, name_property: true
property :policy_command, String, required: true
property :value, Integer, required: true

action :set do
  execute policy_name do
    command "net accounts /#{policy_command}:#{value.to_s}"
    action :run
    not_if { ::File.exist?("C:\\#{policy_name}.lock") }
    notifies :create, "file[C:\\#{policy_name}.lock]", :immediately
  end

  file "C:\\#{policy_name}.lock" do
    action :create
  end
end
