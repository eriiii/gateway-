package main

import (
	_ "context"
	"fmt"
	_ "math/rand"
	"net"
	"runtime"
	"sync"
	_ "time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// capture packet from client and send to server gateway
func capturesend(handle *pcap.Handle, conn net.Conn) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		ip, _ := ipLayer.(*layers.IPv4)
		if ipLayer != nil && udpLayer != nil && ip.SrcIP.String() == "192.168.0.110" {
			fmt.Println(ip.SrcIP, ip.DstIP)
			_, err := conn.Write(ethLayer.LayerPayload())
			if err != nil {
				fmt.Println("conn write err =", err)
				return
			}
			fmt.Println("conn1 packet send")
			fmt.Println("thread =", runtime.NumGoroutine())
		}
	}
}

// received packet back from server side, havent used this function in mptcp
func backread(conn1 net.Conn, ch chan []byte) {
	defer wg.Done()
	for {
		buf1 := make([]byte, 2048)
		n1, err := conn1.Read(buf1[:])
		if err != nil {
			fmt.Println("conn1 read backpacket err = ", err)
			continue
		}
		ch <- buf1[0:n1]
	}
}

// send packet back to client
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
	//ch := make(chan []byte, 64)

	//enable mptcp
	var d net.Dialer
	d.SetMultipathTCP(true)

	//interface name for capture packet, wlp3s0
	handle, err := pcap.OpenLive("wlp3s0", 65535, true, pcap.BlockForever)
	if err != nil {
		fmt.Println("open interface err =", err)
		return
	}
	defer handle.Close()

	//server side gateway ip address
	conn1, err := d.Dial("tcp", "192.168.0.109:14567")
	if err != nil {
		fmt.Println("conn1 dial err= ", err)
		return
	}
	defer conn1.Close()

	//open socket to send packet
	// listen, err := net.ListenUDP("udp", &net.UDPAddr{Port: 17891})
	// if err != nil {
	// 	fmt.Println("listen err =", err)
	// 	return
	// }
	// defer listen.Close()

	//client ip address
	//backaddr, _ := net.ResolveUDPAddr("udp", "10.0.0.116:17399")

	for {
		wg.Add(1)
		go capturesend(handle, conn1)
		// wg.Add(1)
		// go backread(conn1, ch)
		// wg.Add(1)
		// go backsend(listen, backaddr, ch)
		wg.Wait()
	}
}
