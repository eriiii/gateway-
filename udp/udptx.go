package main

import (
	"fmt"
	"net"
	"runtime"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// capture packet from client and send to server gateway
func capturesend(handle *pcap.Handle, conn *net.UDPConn) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	i := 0
	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		ip, _ := ipLayer.(*layers.IPv4)
		//filter packet with ip address and udp, ip.srcip need to be the client ip address
		if ipLayer != nil && udpLayer != nil && ip.SrcIP.String() == "192.168.0.197" {
			// compare it with the ethernet payload decoding at server side, see it match or not
			fmt.Println(ip.SrcIP, ip.DstIP)
			i++
			//send ethernet payload
			_, err := conn.Write(ethLayer.LayerPayload())
			fmt.Println("thread =", runtime.NumGoroutine())
			if err != nil {
				fmt.Println("conn write err =", err)
				return
			} else {
				fmt.Println("packet send", i)
			}
		}
	}
}

// receive packet back from server
func backread(conn *net.UDPConn, ch chan []byte) {
	defer wg.Done()
	for {
		buf := make([]byte, 2048)
		n, _, err := conn.ReadFromUDP(buf[:])
		fmt.Println("113")
		if err != nil {
			fmt.Println("read backpacket err = ", err)
			continue
		}
		ch <- buf[0:n]
	}
}

// send the packet back to client, not using in this case
func backsend(conn *net.UDPConn, addr *net.UDPAddr, ch chan []byte) {
	defer wg.Done()
	for {
		buffer := <-ch
		backpacket := gopacket.NewPacket(buffer, layers.LayerTypeIPv4, gopacket.Default)
		ipbackLayer := backpacket.Layer(layers.LayerTypeIPv4)
		udpbackLayer := backpacket.Layer(layers.LayerTypeUDP)
		if ipbackLayer != nil && udpbackLayer != nil {
			ipback, _ := ipbackLayer.(*layers.IPv4)
			udpback, _ := udpbackLayer.(*layers.UDP)
			fmt.Println(ipback.SrcIP, udpback.SrcPort)
			_, err := conn.WriteTo(backpacket.ApplicationLayer().Payload(), addr)
			if err != nil {
				fmt.Println("back packet send err =", err)
				return
			} else {
				fmt.Println("back packet send")
			}
		}
	}
}

var wg sync.WaitGroup

func main() {
	ch := make(chan []byte, 64)

	//interface name for capture packet, wlp3s0
	handle, err := pcap.OpenLive("wlp3s0", 65535, true, pcap.BlockForever)
	if err != nil {
		fmt.Println("open interface err =", err)
		return
	}
	defer handle.Close()

	//server side gateway ip address
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.IPv4(192, 168, 0, 83),
		Port: 14567,
	})
	if err != nil {
		fmt.Println("dial err= ", err)
		return
	}
	defer conn.Close()

	// open socket to receive packet from server side, not using in this case
	listen, err := net.ListenUDP("udp", &net.UDPAddr{Port: 17891})
	if err != nil {
		fmt.Println("listen err =", err)
		return
	}
	defer listen.Close()

	//client address
	backaddr, _ := net.ResolveUDPAddr("udp", "10.0.0.143:17899")

	for {
		wg.Add(1)
		go capturesend(handle, conn)
		wg.Add(1)
		go backread(conn, ch)
		wg.Add(1)
		go backsend(listen, backaddr, ch)
		wg.Wait()
	}
}
