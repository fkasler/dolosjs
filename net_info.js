const EventEmitter = require('events')
const dns = require('dns')
const dhcp = require('dhcp')
const dgram = require('dgram');
//pcap class to set up network listeners
var pcap = require('pcap')
//custom class to track arp entries, update ARP for NetInfo, and update ARP for our BridgeController
const ArpTable = require('./arp_table.js')

//try to leverage DHCP to get some of this info
const DHCP_PROTOCOL = require('./node_modules/dhcp/lib/protocol.js')

const { execSync } = require("child_process")

class NetInfo extends EventEmitter {

  constructor(network_interface) {
    super()
    this.network_interface = network_interface
    this.arp_table = new ArpTable(network_interface)
    this.client_mac = ''
    this.client_ip = ''
    this.client_name = ''
    this.client_ttl = ''
    this.gateway_mac = ''
    this.gateway_ip = ''
    this.dns_servers = []
    this.search_domain = ''
    this.subnet = ''
    this.subnet_mask = ''
    this.dhcp_server = ''
    this.ntp_server = ''
    this.kerberos_server = ''

    var netinfo = this
    this.gateway_search_tap = pcap.createSession(network_interface, { filter: "ip" })
    this.dns_search_tap

    netinfo.gateway_search_tap.on('packet', function (raw_packet) {
      let packet = pcap.decode.packet(raw_packet)
      netinfo.gateway_search(packet)
    })

    var arp_table = this.arp_table
    arp_table.on('arp_entry', function(arp_info){
      netinfo.arp_entry(arp_info)
    })
  }

  
  gateway_search(packet){
    var netinfo = this
    let ip_info = netinfo.get_ip_info(packet)
    if(typeof netinfo.arp_table.entries[ip_info.smac.toString()] != 'undefined'){
      //avoid broadcast issues
      if(ip_info.dmac.toString() != 'ff:ff:ff:ff:ff:ff'){
      //mismatch with our collected ARP table means it's a gateway to another IP subnet (aka our gateway)
        if(ip_info.shost.toString() != netinfo.arp_table.entries[ip_info.smac.toString()]){
          console.log(`Gateway IP:\t${netinfo.arp_table.entries[ip_info.smac.toString()]}`)
          netinfo.update_value('gateway_ip', netinfo.arp_table.entries[ip_info.smac.toString()], 'Found Gateway IP from ARP Mismatch', ip_info)
          console.log(`Gateway MAC:\t${ip_info.smac.toString()}`)
          netinfo.update_value('gateway_mac', ip_info.smac.toString(), 'Found Gateway MAC from ARP Mismatch', ip_info)
          console.log(`Host IP:\t${ip_info.dhost.toString()}`)
          netinfo.update_value('client_ip', ip_info.dhost.toString(), 'Found Client IP from ARP Mismatch', ip_info)
          console.log(`Host MAC:\t${ip_info.dmac.toString()}`)
          netinfo.update_value('client_mac', ip_info.dmac.toString(), 'Found Gateway MAC from ARP Mismatch', ip_info)
          this.emit('client_ip_mac_and_gateway_mac', this.print_info())
          this.emit('gateway_ip_mac_and_client_mac', this.print_info())
          netinfo.client_mac = ip_info.dmac.toString()
          netinfo.start_ttl_search()
        }
      }
    }
    if(typeof netinfo.arp_table.entries[ip_info.dmac.toString()] != 'undefined'){
      //avoid broadcast issues
      if(ip_info.dmac.toString() != 'ff:ff:ff:ff:ff:ff'){
        //avoid multicast issues
        //https://stackoverflow.com/questions/1503893/validate-ip-address-is-not-0-0-0-0-or-multicast-address#:~:text=If%20you%20first%20convert%20the,logic%20used%20in%20Java%20Inet4Address.
        if((ip_info.dhost.addr[0] & 0xF0) != 0xE0){
          //mismatch with our collected ARP table means it's a gateway to another IP subnet (aka our gateway)
          if(ip_info.dhost.toString() != netinfo.arp_table.entries[ip_info.dmac.toString()]){
            console.log(`Gateway IP:\t${netinfo.arp_table.entries[ip_info.dmac.toString()]}`)
            netinfo.update_value('gateway_ip', netinfo.arp_table.entries[ip_info.dmac.toString()], 'Found Gateway IP from ARP Mismatch', ip_info)
            console.log(`Gateway MAC:\t${ip_info.dmac.toString()}`)
            netinfo.update_value('gateway_mac', ip_info.dmac.toString(), 'Found Gateway MAC from ARP Mismatch', ip_info)
            console.log(`Host IP:\t${ip_info.shost.toString()}`)
            netinfo.update_value('client_ip', ip_info.shost.toString(), 'Found Clinet IP from ARP Mismatch', ip_info)
            console.log(`Host MAC:\t${ip_info.smac.toString()}`)
            netinfo.update_value('client_mac', ip_info.smac.toString(), 'Found Client AMC from ARP Mismatch', ip_info)
            console.log(`Host TTL:\t${ip_info.ttl.toString()}`)
            netinfo.update_value('client_ttl', ip_info.ttl.toString(), 'Found Client TTL from ARP Mismatch', ip_info)
            this.emit('client_ip_mac_and_gateway_mac', this.print_info())
            this.emit('gateway_ip_mac_and_client_mac', this.print_info())
            this.emit('client_ttl', this.print_info())
            netinfo.start_dns_search()
          }
        }
      }
    }
  }
  
  start_ttl_search(){
    var netinfo = this
    netinfo.gateway_search_tap.removeAllListeners()
    netinfo.gateway_search_tap.on('packet', function (raw_packet) {
      let packet = pcap.decode.packet(raw_packet)
      netinfo.ttl_search(packet)
    })
  }
  
  ttl_search(packet){
    var netinfo = this
    let ip_info = netinfo.get_ip_info(packet)
    if(ip_info.smac.toString() == this.client_mac){
      console.log(`Host TTL:\t${ip_info.ttl.toString()}`)
      netinfo.update_value('client_ttl', ip_info.ttl.toString(), 'Found Client TTL From Packet Coming From Client', ip_info)
      this.emit('client_ttl', this.print_info())
      netinfo.start_dns_search()
    }
  }
  
  start_dns_search(){
    var netinfo = this
    netinfo.gateway_search_tap.removeAllListeners()
    netinfo.gateway_search_tap.close()
    console.log('starting DNS Tap')
    netinfo.dns_search_tap = pcap.createSession(netinfo.network_interface, { filter: "ip proto \\udp and (port 53 or 67 or 68)" })
    netinfo.dns_search_tap.on('packet', function (raw_packet) {
      let packet = pcap.decode.packet(raw_packet)
      netinfo.dns_search(packet)
    })
  }
  
  dns_search(packet){
    var netinfo = this
    let ip_info = netinfo.get_ip_info(packet)
    if(ip_info.dport == 53){
      console.log(`DNS Server:\t${ip_info.dhost}`)
      netinfo.update_dns(ip_info.dhost, ip_info)
      netinfo.dns_search_tap.removeAllListeners()
      netinfo.dns_search_tap.close()
    }
  
    if(ip_info.sport == 53){
      console.log(`DNS Server:\t${ip_info.shost}`)
      netinfo.update_dns(ip_info.shost, ip_info)
      //netinfo.dns_search_tap.removeAllListeners()
      //netinfo.dns_search_tap.close()
    }
  
    if((ip_info.dport == 67) && (ip_info.smac.toString() == this.client_mac)){
      let dhcp_data = DHCP_PROTOCOL.parse(packet.payload.payload.payload.data)
      if(typeof dhcp_data.options['12'] != 'undefined'){
        console.log(`Host Name: ${dhcp_data.options['12']}`)
        netinfo.update_value('client_name', dhcp_data.options['12'], 'Found Hostname from DHCP', ip_info)
      } 
    }
  
    if(ip_info.dport == 68){
      let dhcp_data = DHCP_PROTOCOL.parse(packet.payload.payload.payload.data)
      //not reliable due to broadcast nature
      if(typeof dhcp_data.options['1'] != 'undefined'){
        console.log(`Subnet Mask:\t${dhcp_data.options['1']}`)
        netinfo.update_value('subnet_mask', dhcp_data.options['1'], 'Found Subnet from DHCP', ip_info)
      }
      if(typeof dhcp_data.options['12'] != 'undefined'){
        console.log(`DHCP Server:\t${dhcp_data.options['12']}`)
        netinfo.update_value('dhcp_server', dhcp_data.options['12'], 'Found DHCP Server from DHCP', ip_info)
      }
      if(typeof dhcp_data.options['42'] != 'undefined'){
        console.log(`NTP Server:\t${dhcp_data.options['42'][0]}`)
        netinfo.update_value('ntp_server', dhcp_data.options['42'][0], 'Found NTP Server from DHCP', ip_info)
      }
      if(typeof dhcp_data.options['15'] != 'undefined'){
        console.log(`Search Domain:\t${dhcp_data.options['15']}`)
        netinfo.update_value('search_domain', dhcp_data.options['15'], 'Found Search Domain IP from DHCP', ip_info)
      }
      if(typeof dhcp_data.options['6'] != 'undefined'){
        let dns_servers = dhcp_data.options['6']
        let netinfo = this
        dns_servers.forEach(function(server){
          netinfo.update_dns(server, ip_info)
          console.log(`DNS Server:\t${server}`)
        })
        netinfo.dns_search_tap.removeAllListeners()
        netinfo.dns_search_tap.close()
      }
    }
  }

  arp_entry(arp_info){
    this.emit('arp_entry', arp_info)
  }

  update_value(key, value, message, packet_info){
    if((this[key] == '') && (value != 'ff:ff:ff:ff:ff:ff')){
      this[key] = value.toString()
      console.log(message)
      console.log(`${packet_info.shost} (${packet_info.smac}):${packet_info.sport} --> ${packet_info.dhost} (${packet_info.dmac}):${packet_info.dport}`)
      console.log(`${key}: ${value}`)
      this.emit('network_update')
    }
  }

  lookup_hostname(){
    if((this.client_name == '') && (this.client_ip != '')){
      dns.reverse(this.client_ip, (err, hosts) => {
        if(err){
          console.log(err)
          //this.client_name = 'not known'
        }else{
          this.client_name = hosts[0]
          console.log(`Hosts: ${JSON.stringify(hosts)}`)
        }
      })
    }
  }

  update_dns(server, packet_info){
    if(this.dns_servers.indexOf(server.toString()) == -1){
      this.dns_servers.push(server.toString())
      console.log('DNS Packet Detected')
      console.log(`${packet_info.shost} (${packet_info.smac}):${packet_info.sport} --> ${packet_info.dhost} (${packet_info.dmac}):${packet_info.dport}`)
      console.log(`dns servers: ${this.dns_servers}`)
      this.emit('dns_update', this.dns_servers)
    }
  }

  get_ip_info(packet){
    let ether = packet.payload
    let ip = ether.payload
    let payload = ip.payload
    let ip_info = {
      "smac": ether.shost,
      "dmac": ether.dhost,
      "shost": ip.saddr,
      "dhost": ip.daddr,
      "sport": payload.sport,
      "dport": payload.dport,
      "ttl": ip.ttl
    }
    return ip_info
  }

  print_info(){
    return {
      "client_mac": this.client_mac,
      "client_ip": this.client_ip, 
      "client_name": this.client_name, 
      "client_ttl": this.client_ttl, 
      "gateway_mac": this.gateway_mac, 
      "gateway_ip": this.gateway_ip, 
      "dns_servers": this.dns_servers, 
      "subnet": this.subnet, 
      "search_domain": this.search_domain, 
      "subnet_mask": this.subnet_mask, 
      "dhcp_server": this.dhcp_server, 
      "ntp_server": this.ntp_server, 
      "kerberos_server": this.kerberos_server,
    }
  }
}

module.exports = NetInfo 
