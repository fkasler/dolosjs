var dateFormat = require('dateformat')
const fs = require('fs')
const EventEmitter = require('events')
const config = require('./config.js')
const fastify = require('fastify')({
  logger: true,
  bodyLimit: 19922944
})

fastify.register(require('fastify-socket.io'), {})

console.log(fs.readFileSync(__dirname + "/banner.txt", "utf8"))
console.log(config)

var macs = JSON.parse(fs.readFileSync(__dirname + "/mac_to_vendor.js", "utf8"))

//read keystrokes from cmdline
const readline = require('readline')
readline.emitKeypressEvents(process.stdin)
process.stdin.setRawMode(true)

//custom class to manage the bridge interface, set iptables/ebtables/arptables rules, and update system network info 
const BridgeController = require('./bridge_controller.js')

var bridge_controller = new BridgeController(config)
bridge_controller.start_bridge()

process.stdin.on('keypress', (str, key) => {
  if (key.ctrl && key.name === 'c') {
    bridge_controller.flush_tables(true)
  } else if (key.name === 'i') {
    console.log("Network Info")
    console.log(JSON.stringify(bridge_controller.net_info.print_info(), null, 4))
    console.log("ARP Table")
    console.log(JSON.stringify(bridge_controller.net_info.arp_table.entries,null, 4))
  }
})

//favicon
fastify.route({
    method: ['GET'],
    url: '/favicon.ico',
    handler: async function (req, reply) {
        let stream = fs.createReadStream(__dirname + "/resources/misc/favicon.ico")
        reply.type('image/x-icon').send(stream)
    }
})

//basic homepage. You can mod it to look like a normal server of your choosing
fastify.route({
    method: ['GET'],
    url: '/',
    handler: async function (req, reply) {
        let stream = fs.createReadStream(__dirname + "/resources/pages/homepage.html")
        reply.type('text/html').send(stream)
    }
})

//static .js files
fastify.route({
    method: ['GET'],
    url: '/static/js/*',
    handler: async function (req, reply) {
        let stream = fs.createReadStream(__dirname + "/resources/js/" + req.params['*'])
        reply.type('text/javascript').send(stream)
    }
})

//static .css files
fastify.route({
    method: ['GET'],
    url: '/static/css/*',
    handler: async function (req, reply) {
        let stream = fs.createReadStream(__dirname + "/resources/styles/" + req.params['*'])
        reply.type('text/css').send(stream)
    }
})

//favicon
fastify.route({
    method: ['GET'],
    url: '/current_log',
    handler: async function (req, reply) {
        let stream = fs.createReadStream(__dirname + "/logs/current.log")
        reply.type('text').send(stream)
    }
})

//overwrite default route to allow Internet traffic from the bridge interface
fastify.route({
    method: ['GET'],
    url: '/allow_internet_traffic',
    handler: async function (req, reply) {
        bridge_controller.allow_internet_traffic()
        reply.send('added default route via mibr')
    }
})

//force reverse lookup of client hostname
fastify.route({
    method: ['GET'],
    url: '/lookup_hostname',
    handler: async function (req, reply) {
        bridge_controller.net_info.lookup_hostname()
        reply.send('Performing reverse lookup')
    }
})

//force a DHCP Discover message to the network
fastify.route({
    method: ['GET'],
    url: '/send_dhcp_probe',
    handler: async function (req, reply) {
        bridge_controller.net_info.send_dhcp_probe()
        reply.send('Performing DHCP Discover')
    }
})

//look up a vendor for a MAC address
fastify.route({
    method: ['GET'],
    url: '/get_vendor',
    handler: async function (req, reply) {
      var mac_addr = req.query['mac_addr']
      while(mac_addr != ""){
        mac_addr = mac_addr.toUpperCase()
        if(macs[mac_addr] != undefined){
          reply.send(macs[mac_addr])
          return
        }else{
          mac_addr = mac_addr.slice(0, mac_addr.length - 1)
        }
      }
      reply.send("unknown")
    }
})

//catch any node exceptions instead of exiting
process.on('uncaughtException', function (err) {
  console.log(dateFormat("isoDateTime") + " " + 'Caught exception: ', err)
})

fastify.ready(function(err){
    if (err) throw err
    fastify.io.on('connect', function(socket){
        console.info('Socket connected!', socket.id)
        bridge_controller.on("bridge_update", function(data) {
            fastify.io.emit("bridge_update", data)
        })
      socket.on('get_update', function(){
        let net_info = bridge_controller.net_info.print_info()
        fastify.io.emit("network_info", net_info)
        let arp_info = bridge_controller.net_info.print_info()
        fastify.io.emit("arp_info", bridge_controller.net_info.arp_table.entries)
      })
    })
})

// Run the server!
const start = async () => {
  fastify.listen(4444, (err) => {
    if (err) {
      fastify.log.error(err)
      process.exit(1)
    }
    fastify.log.info(`server listening on ${fastify.server.address().port}`)
  })
}
start()
