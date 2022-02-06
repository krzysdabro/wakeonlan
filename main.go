package main

import (
	"errors"
	"fmt"
	"log"
	"net"
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
	log.SetFlags(0)
	flag.Parse()

	iface, err := getInterface()
	if err != nil {
		log.Fatal(err)
	}

	hw, err := net.ParseMAC(flag.Arg(0))
	if err != nil {
		log.Fatalf("cannot parse MAC address: %s", err)
	}

	if err := sendPacket(iface, hw); err != nil {
		log.Fatalf("cannot send a packet: %s", err)
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

func getInterface() (*net.Interface, error) {
	if fInterface != nil && *fInterface != "" {
		i, err := net.InterfaceByName(*fInterface)
		if err != nil {
			return nil, fmt.Errorf("cannot get interface %q: %s", *fInterface, err)
		}

		if err := checkInterface(i); err != nil {
			return nil, err
		}

		return i, nil
	}

	ifs, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("cannot list interfaces: %s", err)
	}

	for _, i := range ifs {
		if err := checkInterface(&i); err != nil {
			continue
		}

		return &i, nil
	}

	return nil, errors.New("cannot find suitable interface")
}

func checkInterface(iface *net.Interface) error {
	if (iface.Flags & net.FlagLoopback) == net.FlagLoopback {
		return fmt.Errorf("interface %q is a loopback", iface.Name)
	}

	if (iface.Flags & net.FlagUp) == 0 {
		return fmt.Errorf("interface %q is down", iface.Name)
	}

	addrs, err := iface.Addrs()
	if len(addrs) == 0 || err != nil {
		return fmt.Errorf("interface %q does not have any addresses", iface.Name)
	}

	return nil
}
