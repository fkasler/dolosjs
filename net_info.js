const EventEmitter = require('events')
const dns = require('dns')
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

    //listen for DNS(53), DHCP(67,68), NTP(123), and KERBEROS(88) for UDP indicators
    var udp_listener = pcap.createSession(network_interface, { filter: "ip proto \\udp and (port 53 or 67 or 68 or 123 or 88)" })
    udp_listener.on('packet', function (raw_packet) {
      let packet = pcap.decode.packet(raw_packet)
      netinfo.udp_packet(packet)
    })

    //listen for HTTP/S(80,443), and FTP(21) for TCP indicators
    var tcp_listener = pcap.createSession(network_interface, { filter: "ip proto \\tcp and (port 80 or 443 or 21)" })
    tcp_listener.on('packet', function (raw_packet) {
      let packet = pcap.decode.packet(raw_packet)
      netinfo.tcp_packet(packet)
    })
    
    var arp_table = this.arp_table
    arp_table.on('arp_entry', function(arp_info){
      netinfo.arp_entry(arp_info)
    })
    arp_table.on('new_arp', function(arp_info){
      netinfo.new_arp(arp_info)
    })
  }
  
  check_spoof(info){
    if((info.client_ip != '') && (info.client_mac != '') && (info.gateway_mac != '')){
      this.emit('client_ip_mac_and_gateway_mac', this.print_info())
    }
    if((info.gateway_ip != '') && (info.gateway_mac != '') && (info.client_mac != '')){
      this.emit('gateway_ip_mac_and_client_mac', this.print_info())
    }
    if(info.client_ttl != ''){
      this.emit('client_ttl', this.print_info())
    }
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
      "kerberos_server": this.kerberos_server
    }
  }

  send_dhcp_probe(){
    if((this.client_ip != '') && (this.client_mac != '')){
      // Formulate the response object
      const ans = {
        op: 1,
        htype: 1, // RFC1700, hardware types: 1=Ethernet, 2=Experimental, 3=AX25, 4=ProNET Token Ring, 5=Chaos, 6=Tokenring, 7=Arcnet, 8=FDDI, 9=Lanstar (keep it constant)
        hlen: 6, // Mac addresses are 6 byte
        hops: 0,
        xid: Math.round(Math.random() * (parseInt('ffffffff', 16) - 1) + 1), // Selected by client on DHCPDISCOVER
        secs: 0, // 0 or seconds since DHCP process started
        flags: 0, // 0 or 0x80 (if client requires broadcast reply)
        ciaddr: '0.0.0.0', // 0 for DHCPDISCOVER, other implementations send currently assigned IP - but we follow RFC
        yiaddr: '0.0.0.0',
        siaddr: '0.0.0.0',
        giaddr: '0.0.0.0',
        chaddr: this.client_mac,
        sname: '', // unused
        file: '', // unused
        options: {
          57: 1500, // Max message size
          53: 1,
          50: this.client_ip,
          61: this.client_mac, // MAY
          55: [
            1, //Subnet Mask
            3, //Router
            6, //Domain Name Server
            15, //Domain Name
            31, //Perform Router Discover
            33, //Static Route
            42, //NTP Server
            43, //Vendor-Specific Information
            44, //NetBIOS over TCP/IP Name Server
            46, //NetBIOS over TCP/IP Node Type
            47, //NetBIOS over TCP/IP Scope
            119, //Domain Search
            121, //Classless Static Route
            249, //Private/Classless Static Route (Microsoft)
            252 //Private/Proxy autodiscovery 
          ]
        }
      }
      
      //set up some temporary rules to redirect our request to the right IP scheme


      let output = execSync('iptables -t nat -I POSTROUTING -p udp --sport 6868 -j SNAT --to-source 0.0.0.0:68', {"timeout": 10000}).toString()
      if(output.length > 0){
         console.log(`OUTPUT: ${output}`)
      }

      output = execSync('iptables -t nat -I OUTPUT -p udp --dport 67 -j DNAT --to-destination 255.255.255.255:67', {"timeout": 10000}).toString()
      if(output.length > 0){
         console.log(`OUTPUT: ${output}`)
      }

      output = execSync('ip r add 255.255.255.255/32 dev eth0', {"timeout": 10000}).toString()
      if(output.length > 0){
         console.log(`OUTPUT: ${output}`)
      }
    
      var sock = dgram.createSocket({type: 'udp4', reuseAddr: true})
      sock.bind(6868, '0.0.0.0', function() {
        sock.setBroadcast(true)
      })

      var sb = DHCP_PROTOCOL.format(ans)
      
      sock.send(sb._data, 0, sb._w, 67, '255.255.255.255', function(err, bytes) {
        if (err) {
          console.log(err);
        } else {
          console.log('Sent DHCP Discover', bytes, 'bytes');
        }
        output = execSync('ip r del 255.255.255.255/32', {"timeout": 10000}).toString()
        if(output.length > 0){
           console.log(`OUTPUT: ${output}`)
        }
        output = execSync('ip r add 255.255.255.255/32 dev eth1', {"timeout": 10000}).toString()
        if(output.length > 0){
           console.log(`OUTPUT: ${output}`)
        }
        sock.send(sb._data, 0, sb._w, 67, '255.255.255.255', function(err, bytes) {
          if (err) {
            console.log(err);
          } else {
            console.log('Sent DHCP Discover', bytes, 'bytes');
          }
          sock.close()
          output = execSync('ip r del 255.255.255.255/32', {"timeout": 10000}).toString()
          if(output.length > 0){
             console.log(`OUTPUT: ${output}`)
          }
          output = execSync('iptables -t nat -D POSTROUTING -p udp --sport 6868 -j SNAT --to-source 0.0.0.0:68', {"timeout": 10000}).toString()
          if(output.length > 0){
             console.log(`OUTPUT: ${output}`)
          }
          output = execSync('iptables -t nat -D OUTPUT -p udp --dport 67 -j DNAT --to-destination 255.255.255.255:67', {"timeout": 10000}).toString()
          if(output.length > 0){
             console.log(`OUTPUT: ${output}`)
          }
        })
      })
    }
  }

  new_arp(arp_info){
    this.emit('new_arp', arp_info)
  }

  arp_entry(arp_info){
    if((this.gateway_mac != '') && (this.gateway_ip == '')){
      for(var key in this.arp_table.entries){
        if(this.arp_table.entries[key] == this.gateway_mac){
          this.gateway_ip = key
          console.log('Gateway IP Detected from ARP Packet')
          console.log(`sender: ${arp_info.sender_ip} --> ${arp_info.sender_mac}  target: ${arp_info.target_ip} --> ${arp_info.target_mac} `)
          console.log(`gateway ip: ${this.gateway_ip}`)
        }
      }
    }
    if((this.gateway_mac == '') && (this.gateway_ip != '')){
      for(var key in this.arp_table.entries){
        if(key == this.gateway_ip){
          this.gateway_mac = this.arp_table.entries[key]
          console.log('Gateway MAC Detected from ARP Packet')
          console.log(`sender: ${arp_info.sender_ip} --> ${arp_info.sender_mac}  target: ${arp_info.target_ip} --> ${arp_info.target_mac} `)
          console.log(`gateway mac: ${this.gateway_mac}`)
        }
      }
    }
  }

  update_value(key, value, message, packet_info){
    if((this[key] == '') && (value != 'ff:ff:ff:ff:ff:ff')){
      this[key] = value.toString()
      console.log(message)
      console.log(`${packet_info.shost} (${packet_info.smac}):${packet_info.sport} --> ${packet_info.dhost} (${packet_info.dmac}):${packet_info.dport}`)
      console.log(`${key}: ${value}`)
      this.check_spoof(this)
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

  update_value_dhcp(key, value, message){
    if(value.toString() != 'ff:ff:ff:ff:ff:ff'){
      this[key] = value.toString()
      console.log(message)
      console.log(`${key}: ${value}`)
      this.check_spoof(this)
      this.emit('network_update')
    }
  }

  update_dns_dhcp(server){
    if(this.dns_servers.indexOf(server.toString()) == -1){
      this.dns_servers.push(server.toString())
      console.log('DNS Record from DHCP')
      console.log(`dns servers: ${this.dns_servers}`)
      this.emit('dns_update', this.dns_servers)
    }
  }

  http_request(packet_info){
    this.update_value('client_mac', packet_info.smac, 'Client MAC Detected from HTTP Request', packet_info)
    this.update_value('client_ip', packet_info.shost, 'Client IP Detected from HTTP Request', packet_info)
    this.update_value('client_ttl', packet_info.ttl, 'Client TTL Detected from HTTP Request', packet_info)
    let source_first_octet = packet_info.shost.toString().split('.')[0]
    let destination_first_octet = packet_info.dhost.toString().split('.')[0]
    //assume they are not doing some crazy IP scheme and we will need to traverse the gateway to reach another /8
    if(destination_first_octet != source_first_octet){
      this.update_value('gateway_mac', packet_info.dmac, 'Gateway MAC Detected from External HTTP Request', packet_info)
    }
  }

  http_response(packet_info){
    this.update_value('client_mac', packet_info.dmac, 'Client MAC Detected from HTTP Response', packet_info)
    this.update_value('client_ip', packet_info.dhost, 'Client IP Detected from HTTP Response', packet_info)
    let source_first_octet = packet_info.shost.toString().split('.')[0]
    let destination_first_octet = packet_info.dhost.toString().split('.')[0]
    //assume they are not doing some crazy IP scheme and we will need to traverse the gateway to reach another /8
    if(destination_first_octet != source_first_octet){
      this.update_value('gateway_mac', packet_info.smac, 'Gateway MAC Detected from External HTTP Response', packet_info)
    }
  }

  ftp_request(packet_info){
    this.update_value('client_mac', packet_info.smac, 'Client MAC Detected from FTP Request', packet_info)
    this.update_value('client_ip', packet_info.shost, 'Client IP Detected form FTP Request', packet_info)
    this.update_value('client_ttl', packet_info.ttl, 'Client TTL Detected from FTP Request', packet_info)
  }

  ftp_response(packet_info){
    this.update_value('client_mac', packet_info.dmac, 'Client MAC Detected from FTP Response', packet_info)
    this.update_value('client_ip', packet_info.dhost, 'Client IP Detected from FTP Response', packet_info)
  }

  dns_request(packet_info){
    this.update_value('client_mac', packet_info.smac, 'Client MAC Detected from DNS Request', packet_info)
    this.update_value('client_ip', packet_info.shost, 'Client IP Detected from DNS Request', packet_info)
    this.update_value('client_ttl', packet_info.ttl, 'Client TTL Detected from DNS Request', packet_info)
    this.update_dns(packet_info.dhost, packet_info)
  }

  dns_response(packet_info){
    this.update_value('client_mac', packet_info.dmac, 'Client MAC Detected from DNS Response', packet_info)
    this.update_value('client_ip', packet_info.dhost, 'Client IP Detected from DNS Response', packet_info)
    this.update_dns(packet_info.shost, packet_info)
  }

  dhcp_response(packet_info){
    this.update_value('client_mac', packet_info.dmac, 'Client MAC Detected from DHCP Response', packet_info)
    this.update_value('client_ip', packet_info.dhost, 'Client IP Detected from DHCP Response', packet_info)
    this.update_value('dhcp_server', packet_info.shost, 'DHCP Server IP Detected from DHCP Response', packet_info)
  }

  ntp_request(packet_info){
    this.update_value('client_mac', packet_info.smac, 'Client MAC Detected from NTP Request', packet_info)
    this.update_value('client_ip', packet_info.shost, 'Client MAC Detected from NTP Request', packet_info)
    this.update_value('client_ttl', packet_info.ttl, 'Client TTL Detected from NTP Request', packet_info)
    this.update_value('ntp_server', packet_info.dhost, 'NTP Server Detected from NTP Request', packet_info)
  }

  ntp_response(packet_info){
    this.update_value('client_mac', packet_info.dmac, 'Client MAC Detected from NTP Response', packet_info)
    this.update_value('client_ip', packet_info.dhost, 'Client MAC Detected from NTP Response', packet_info)
    this.update_value('ntp_server', packet_info.shost, 'NTP Server Detected from NTP Response', packet_info)
  }

  kerberos_request(packet_info){
    this.update_value('client_mac', packet_info.smac, 'Client MAC Detected from KERBEROS Request', packet_info)
    this.update_value('client_ip', packet_info.shost, 'Client MAC Detected from KERBEROS Request', packet_info)
    this.update_value('client_ttl', packet_info.ttl, 'Client TTL Detected from KERBEROS Request', packet_info)
    this.update_value('kerberos_server', packet_info.dhost, 'KERBEROS Server Detected from KERBEROS Request', packet_info)
  }

  kerberos_response(packet_info){
    this.update_value('client_mac', packet_info.dmac, 'Client MAC Detected from KERBEROS Response', packet_info)
    this.update_value('client_ip', packet_info.dhost, 'Client MAC Detected from KERBEROS Response', packet_info)
    this.update_value('kerberos_server', packet_info.shost, 'KERBEROS Server Detected from KERBEROS Response', packet_info)
  }

  tcp_packet(packet){
    let ether = packet.payload
    let ip = ether.payload
    let tcp = ip.payload
    let tcp_info = {
      "smac": ether.shost,
      "dmac": ether.dhost,
      "shost": ip.saddr,
      "dhost": ip.daddr,
      "sport": tcp.sport,
      "dport": tcp.dport,
      "ttl": ip.ttl
    }
    if((tcp_info.dport == 80) || (tcp_info.dport == 443)){
      this.http_request(tcp_info)
    }else if(tcp_info.dport == 21){
      this.ftp_request(tcp_info)
    }else if((tcp_info.sport == 80) || (tcp_info.sport == 443)){
      this.http_response(tcp_info)
    }else if(tcp_info.sport == 21){
      this.ftp_response(tcp_info)
    }
    if((ip.ttl % 2 == 1) && (ip.ttl != 1) && (ip.ttl != 255)){
      this.update_value('gateway_mac', tcp_info.smac, 'Gatway MAC Detected from Odd TTL', tcp_info)
    }
  }

  udp_packet(packet){
    let ether = packet.payload
    let ip = ether.payload
    let udp = ip.payload
    let udp_info = {
      "smac": ether.shost,
      "dmac": ether.dhost,
      "shost": ip.saddr,
      "dhost": ip.daddr,
      "sport": udp.sport,
      "dport": udp.dport,
      "ttl": ip.ttl
    }
    if(udp_info.dport == 53){
      this.dns_request(udp_info)
    }else if(udp_info.dport == 123){
      this.ntp_request(udp_info)
    }else if(udp_info.dport == 88){
      this.kerberos_request(udp_info)
    }else if(udp_info.sport == 53){
      this.dns_response(udp_info)
    }else if(udp_info.sport == 123){
      this.ntp_response(udp_info)
    }else if(udp_info.sport == 88){
      this.kerberos_response(udp_info)
    }else if(udp_info.dport == 68){
      this.dhcp_response(udp_info)
      //parse out useful info from dhcp
      let dhcp_data
      dhcp_data = DHCP_PROTOCOL.parse(udp.data)
      //not reliable due to broadcast nature
      if(typeof dhcp_data.yiaddr != 'undefined'){
        if((dhcp_data.options['53'] == 5) && (udp_info.dmac == this.client_mac)){
          this.update_value_dhcp('client_ip', dhcp_data.yiaddr, 'Client IP Detected from DHCP')
        }
      }
      if(typeof dhcp_data.options['1'] != 'undefined'){
        this.update_value_dhcp('subnet_mask', dhcp_data.options['1'], 'Subnet Mask Detected from DHCP')
      }
      if((typeof dhcp_data.options['3'] != 'undefined') && (udp_info.dmac == this.client_mac)){
        this.update_value_dhcp('gateway_ip', dhcp_data.options['3'], 'Gateway IP Detected from DHCP')
      }
      if(typeof dhcp_data.options['12'] != 'undefined'){
        console.log(dhcp_data.options['12'])
        this.update_value_dhcp('client_name', dhcp_data.options['12'], 'Host Name Detected from DHCP')
      }
      if(typeof dhcp_data.options['42'] != 'undefined'){
        console.log(dhcp_data.options['42'][0])
        this.update_value_dhcp('ntp_server', dhcp_data.options['42'][0], 'NTP Detected from DHCP')
      }
      if(typeof dhcp_data.options['15'] != 'undefined'){
        console.log(dhcp_data.options['15'])
        this.update_value_dhcp('search_domain', dhcp_data.options['15'], 'Search Domain Detected from DHCP')
      }
      if(typeof dhcp_data.options['6'] != 'undefined'){
        let dns_servers = dhcp_data.options['6']
        let netinfo = this
        dns_servers.forEach(function(server){
          netinfo.update_dns_dhcp(server)
        })
      }
    }
    if(udp_info.dmac == 'ff:ff:ff:ff:ff:ff'){
      console.log('Saw DHCP Discover Message')
      let dhcp_data
      dhcp_data = DHCP_PROTOCOL.parse(udp.data)
      if((typeof dhcp_data.options['12'] != 'undefined') && (udp_info.smac == this.client_mac)){
        this.update_value_dhcp('client_name', dhcp_data.options['12'], 'Host Name Detected from DHCP')
      }
    }
    //Not reliable, but may work in a pinch... May add as a fallback
    //if((ip.ttl % 2 == 1) && (ip.ttl != 1) && (ip.ttl != 255)){
    //  this.update_value('gateway_mac', udp_info.smac, 'Gatway MAC Detected from Odd TTL', udp_info)
    //}
  }

}

module.exports = NetInfo 
