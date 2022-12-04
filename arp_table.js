const EventEmitter = require('events')
var pcap = require('pcap')

class ArpTable extends EventEmitter {
  constructor(network_interface) {
    super()
    this.entries = {}
    var arptable = this

    //listen for ARP so we can manually update the OS arptables
    this.arp_listener = pcap.createSession(network_interface, { filter: "arp" })
    this.arp_listener.on('packet', function (raw_packet) {
      let packet = pcap.decode.packet(raw_packet)
      arptable.arp_packet(packet)
    })
  }

  arp_packet(packet){
    let ether = packet.payload
    let arp = ether.payload
    let arp_info = {
      "operation": arp.operation,
      "sender_mac": arp.sender_ha,
      "sender_ip": arp.sender_pa,
      "target_mac": arp.target_ha,
      "target_ip": arp.target_pa
    }
    //log arp requests
    if(arp_info.operation == 1){
      if(arp_info.sender_ip.toString() != '0.0.0.0'){
        this.entries[arp_info.sender_mac.toString()] = arp_info.sender_ip.toString()
        this.emit('arp_entry', arp_info)
      }
    }
    //log arp responses
    if(arp_info.operation == 2){
      if(arp_info.sender_ip.toString() != '0.0.0.0'){
        this.entries[arp_info.sender_mac.toString()] = arp_info.sender_ip.toString()
      }
      if(arp_info.target_ip.toString() != '0.0.0.0'){
        this.entries[arp_info.target_mac.toString()] = arp_info.target_ip.toString()
        this.emit('arp_entry', arp_info)
      }
    }
  }

  close(){
    this.arp_listener.close()
  }

}

module.exports = ArpTable
