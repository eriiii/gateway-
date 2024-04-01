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
func capturesend(handle *pcap.Handle, conn *net.TCPConn) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		ip, _ := ipLayer.(*layers.IPv4)
		//filter packet with ip address and udp, ip.srcip need to be the client ip address
		if ipLayer != nil && udpLayer != nil && ip.SrcIP.String() == "192.168.0.197" {
			// compare it with the ethernet payload decoding at server side, see it match or not
			fmt.Println(ip.SrcIP, ip.DstIP)
			//send ethernet payload
			_, err := conn.Write(ethLayer.LayerPayload())
			fmt.Println("thread =", runtime.NumGoroutine())
			if err != nil {
				fmt.Println("conn write err =", err)
				return
			} else {
				fmt.Println("packet send")
			}
		}
	}
}

// received packet back from server side
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

	//interface name for capture packet, wlp3s0
	handle, err := pcap.OpenLive("wlp3s0", 65535, true, pcap.BlockForever)
	if err != nil {
		fmt.Println("open interface err =", err)
		return
	}
	defer handle.Close()

	//server side gateway ip address, _ can replace by err
	tcpAddr, _ := net.ResolveTCPAddr("tcp", "192.168.0.109:14789")

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		fmt.Println("dial err= ", err)
		return
	}
	defer conn.Close()

	//set send buffer length
	err = conn.SetWriteBuffer(512 * 1024 * 1024)
	if err != nil {
		fmt.Println("set buffer err ", err)
		return
	}

	//open socket to send packet
	// listen, err := net.ListenUDP("udp", &net.UDPAddr{Port: 17891})
	// if err != nil {
	// 	fmt.Println("listen err =", err)
	// 	return
	// }
	// defer listen.Close()

	//client ip address
	//backaddr, _ := net.ResolveUDPAddr("udp", "10.0.0.143:17899")

	for {
		wg.Add(1)
		go capturesend(handle, conn)
		// wg.Add(1)
		// go backread(conn, ch)
		// wg.Add(1)
		// go backsend(listen, backaddr, ch)
		wg.Wait()
	}
}
