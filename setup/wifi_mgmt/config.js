var config = module.exports = {}

config.network_interface1 = 'eth0'
config.network_interface2 = 'eth1'
config.management_subnet = '172.31.255.0/24'
config.replace_default_route = false
config.run_command_on_success = false
config.autorun_command = 'date > /root/tools/dolosjs/cmd_test.txt'
