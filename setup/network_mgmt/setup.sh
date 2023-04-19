#!/bin/bash 

#update repos
apt update
#update os
apt -y upgrade

#install deps that are absolutely required for the project to work
apt --assume-yes install nodejs npm libpcap0.8-dev bridge-utils iptables ebtables arptables network-manager make g++

#install other standard software to make life easier
apt --assume-yes install vim tmux screen zip unzip dnsutils curl

#force the interfaces to be named with predictable conventions. This allows us to easliy swap our Ethernet NIC etc. and know we can reference it in udhcpd and /etc/network/interfaces as eth2
ln -s /dev/null /etc/systemd/network/99-default.link

#set up configs for wlan0 as management interface
cp ./config.js ../../

#ask the tech for their multiplexer pref
promptanswered=0
while [[ $promptanswered == 0 ]]; do
    read -p 'Which multiplexer do you want to use for the dolos service?(tmux/screen) ' servicechoice
    servicechoice=${servicechoice,,} #tolower
    if [[ $servicechoice == "tmux" ]]; then
        sed -i 's/#tmux/tmux/' etc_init.d_dolos_service
        promptanswered=1
    elif [[ $servicechoice == "screen" ]]; then
        sed -i 's/#screen/screen/' etc_init.d_dolos_service
        promptanswered=1
    fi
done
cp ./etc_init.d_dolos_service /etc/init.d/dolos_service
chmod +x /etc/init.d/dolos_service

#install Node.js deps
cd ../../
npm install

echo "All set up! Reboot and check that your management network is running and accessible"
echo "Then you can 'bash finish_setup.sh' to autorun the attack"
