#!/bin/bash 
cp ./etc_network_interfaces.d_eth0 /etc/network/interfaces.d/eth0 
cp ./etc_network_interfaces.d_eth1 /etc/network/interfaces.d/eth1 
systemctl enable dolos_service
