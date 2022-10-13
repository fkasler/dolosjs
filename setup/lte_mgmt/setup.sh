#!/bin/bash 

#update repos
apt update
#update os
apt -y upgrade

#install deps that are absolutely required for the project to work
apt --assume-yes install nodejs npm libpcap0.8-dev bridge-utils ebtables arptables network-manager

#install Zerotier as callback method
dpkg -i zerotier-one_1.4.6_arm64.deb

#try config file before install...
cp ./etc_wvdial.conf /etc/wvdial.conf 

#install deps for USB Modem as management interface
apt --assume-yes install ppp usb-modeswitch wvdial

#install other standard software to make life easier
apt --assume-yes install vim tmux screen zip unzip dnsutils curl

#force the interfaces to be named with predictable conventions. This allows us to easliy swap our WiFi NIC etc. and know we can reference it in hostapd and /etc/network/interfaces as wlan0
ln -s /dev/null /etc/systemd/network/99-default.link

#set up some configs for the interfaces and wvdial
cp ./config.js ../../
cp ./etc_init.d_dolos_service /etc/init.d/dolos_service 
cp ./etc_ppp_ip-up.d_dolos_callback /etc/ppp/ip-up.d/dolos_callback 
cp ./etc_usb_modeswitch.conf /etc/usb_modeswitch.conf 
cp ./etc_usb_modeswitch.d_12d1_1505 /etc/usb_modeswitch.d/12d1:1505
chmod +x /etc/init.d/dolos_service
chmod +x /etc/ppp/ip-up.d/dolos_callback 

#reload the daemons after all those changes
systemctl daemon-reload

#install Node.js deps
cd ../../
npm install

echo "All set up! Check that your callback is working"
echo "I mean seriously test this to make sure you don't brick the box and have to start over"
echo "Then you can run 'bash finish_setup.sh' AND modify /etc/init.d/dolos_service to uncomment the screen/tmux line and autorun the attack"
