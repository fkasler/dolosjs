package main

import (
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() {
	ifname := os.Args[1]

	// https://plasmixs.github.io/raw-sockets-programming-in-c.html
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	check(err)
	defer syscall.Close(fd)

	iface, err := net.InterfaceByName(ifname)
	check(err)
	check(syscall.BindToDevice(fd, ifname))
	check(syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1))

	xid := rand.Uint32()

	dst := syscall.SockaddrInet4{
		Port: 67,
		Addr: [4]byte{255, 255, 255, 255},
	}

	eth := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       layers.EthernetBroadcast,
	}
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    []byte{0, 0, 0, 0},
		DstIP:    dst.Addr[:],
		Protocol: layers.IPProtocolUDP,
	}
	udp := layers.UDP{
		SrcPort: 68,
		DstPort: layers.UDPPort(dst.Port),
	}
	dhcp := layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		ClientHWAddr: iface.HardwareAddr,
		Xid:          xid,
	}

	appendOption := func(optType layers.DHCPOpt, data []byte) {
		dhcp.Options = append(dhcp.Options, layers.DHCPOption{
			Type:   optType,
			Data:   data,
			Length: uint8(len(data)),
		})
		return
	}

	appendOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeDiscover)})
	appendOption(layers.DHCPOptHostname, []byte("foobar"))
	appendOption(layers.DHCPOptParamsRequest,
		[]byte{
			1,  // Subnet Mask
			3,  // Router
			6,  // Domain Name Server
			26, // Interface MTU
			42, // Network Time Protocol Servers
		},
	)

	udp.SetNetworkLayerForChecksum(&ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	check(gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp, &dhcp))
	data := buf.Bytes()

	ethAddr := syscall.SockaddrLinklayer{
		Halen:   6,
		Addr:    [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		Ifindex: iface.Index,
	}

	log.Printf("sending %d bytes", len(data))
	check(syscall.Sendto(fd, data, 0, &ethAddr))

	go func() {
		recvBuf := make([]byte, 1500)

		read, sockaddr, err := syscall.Recvfrom(fd, recvBuf, 0)
		log.Println(read, "bytes read from", sockaddr)
		check(err)
	}()

	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGINT)
	log.Println("received", <-c)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

// htons converts a short (uint16) from host-to-network byte order.
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}
