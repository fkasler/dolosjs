#!/bin/bash 
cp ./etc_network_interfaces.d_eth0 /etc/network/interfaces.d/eth0 
cp ./etc_network_interfaces.d_eth1 /etc/network/interfaces.d/eth1 
cp ./etc_NetworkManager_conf.d_99-unmanaged-devices.conf /etc/NetworkManager/conf.d/99-unmanaged-devices.conf
systemctl enable dolos_service
