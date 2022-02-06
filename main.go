package main

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	flag "github.com/spf13/pflag"
)

var (
	fInterface *string = flag.StringP("interface", "i", "", "interface name")
)

func main() {
	flag.Parse()

	var iface *net.Interface

	if fInterface != nil && *fInterface != "" {
		i, err := net.InterfaceByName(*fInterface)
		if err != nil {
			fmt.Printf("Cannot get interface %q: %s\n", *fInterface, err)
			os.Exit(1)
		}

		if err := checkInterface(i); err != nil {
			fmt.Printf("Cannot use interface %q: %s\n", *fInterface, err)
			os.Exit(1)
		}

		iface = i
	} else {
		ifs, err := net.Interfaces()
		if err != nil {
			fmt.Printf("Cannot list interfaces: %s\n", err)
			os.Exit(1)
		}

		for _, i := range ifs {
			if err := checkInterface(&i); err != nil {
				continue
			}

			iface = &i
			break
		}

		if iface == nil {
			fmt.Printf("Cannot find suitable interface\n", err)
			os.Exit(1)
		}
	}

	hw, err := net.ParseMAC(flag.Arg(0))
	if err != nil {
		fmt.Printf("Cannot parse MAC address: %s\n", err)
		os.Exit(1)
	}

	if err := sendPacket(iface, hw); err != nil {
		fmt.Printf("Cannot send a packet: %s\n", err)
		os.Exit(1)
	}
}

func sendPacket(iface *net.Interface, hwAddr net.HardwareAddr) error {
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	ethLayer := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       layers.EthernetBroadcast,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := layers.IPv4{
		Version:  4,
		SrcIP:    net.IPv4zero,
		DstIP:    net.IPv4bcast,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
	}
	udpLayer := layers.UDP{
		DstPort: layers.UDPPort(9),
	}
	udpLayer.SetNetworkLayerForChecksum(&ipLayer)
	payload := append(
		[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		[]byte(strings.Repeat(string(hwAddr), 16))...,
	)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, &ethLayer, &ipLayer, &udpLayer, gopacket.Payload(payload)); err != nil {
		return err
	}

	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return err
	}

	return nil
}

func checkInterface(iface *net.Interface) error {
	if (iface.Flags & net.FlagLoopback) == net.FlagLoopback {
		return fmt.Errorf("interface is a loopback", iface.Name)
	}

	if (iface.Flags & net.FlagUp) == 0 {
		return fmt.Errorf("interface is down", iface.Name)
	}

	addrs, err := iface.Addrs()
	if len(addrs) == 0 || err != nil {
		return fmt.Errorf("interface does not have any address")
	}

	return nil
}
