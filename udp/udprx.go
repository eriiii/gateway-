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

// func received packet from client gateway
func read(listen *net.UDPConn, ch chan []byte, addrch chan *net.UDPAddr) {
	defer wg.Done()
	j := 0
	for {
		buf := make([]byte, 2048)
		n, addr, err := listen.ReadFromUDP(buf[:])
		j++
		if err != nil {
			fmt.Println("udp read err = ", err)
			continue
		}
		fmt.Println("packet red ", j)

		//taking the Ip layer payload and decoding
		packet := gopacket.NewPacket(buf[0:n], layers.LayerTypeIPv4, gopacket.Default)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if ipLayer != nil && udpLayer != nil {
			ip := ipLayer.(*layers.IPv4)
			udp := udpLayer.(*layers.UDP)
			//ip of client and destination
			fmt.Println(ip.SrcIP, ip.DstIP, udp.SrcPort)
			//push the data into buffer
			ch <- packet.ApplicationLayer().Payload()
			select {
			case addrch <- addr:
			default:
				continue
			}
		}
	}
}

// func forward packet to server
func forward(listen *net.UDPConn, addr *net.UDPAddr, ch chan []byte) {
	defer wg.Done()
	i := 0
	for {
		fmt.Println("ch len", len(ch))
		//read the buffer and send data to server
		buffer := <-ch
		_, err := listen.WriteToUDP(buffer, addr)
		i++
		if err != nil {
			fmt.Println("sending err = ", err)
			return
		} else {
			fmt.Println("packet forward", i)
		}
	}

}

// func getting packet from server and forward to client gateway,not using
func backward(handle *pcap.Handle, listen *net.UDPConn, addrch chan *net.UDPAddr) {
	backpacketSource := gopacket.NewPacketSource(handle, handle.LinkType())
	backaddr := <-addrch
	for backpacket := range backpacketSource.Packets() {
		ipbackLayer := backpacket.Layer(layers.LayerTypeIPv4)
		ethbackLayer := backpacket.Layer(layers.LayerTypeEthernet)
		udpbackLayer := backpacket.Layer(layers.LayerTypeUDP)
		ipback, _ := ipbackLayer.(*layers.IPv4)
		if ipbackLayer != nil && udpbackLayer != nil && ipback.SrcIP.String() == "10.0.0.116" {
			fmt.Println(ipback.SrcIP, ipback.DstIP)
			_, err := listen.WriteToUDP(ethbackLayer.LayerPayload(), backaddr)
			if err != nil {
				fmt.Println("send back err = ", err)
				return
			}
			fmt.Println("packet backward")
			fmt.Println("thread = ", runtime.NumGoroutine())
		}
	}

}

var wg sync.WaitGroup

func main() {
	//ch store data, addrch store address
	ch := make(chan []byte, 1024)
	addrch := make(chan *net.UDPAddr, 1024)

	// server gateway ip address
	listen, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv4(192, 168, 0, 199),
		Port: 14567,
	})
	if err != nil {
		fmt.Println("listen err = ", err)
	}
	defer listen.Close()

	//open the interface, here enp0s9
	handle, err := pcap.OpenLive("enp0s9", 65536, true, pcap.BlockForever)
	if err != nil {
		fmt.Printf("%s\n", err.Error())
		return
	}
	defer handle.Close()

	//server address
	dstAddr, _ := net.ResolveUDPAddr("udp", "10.0.0.116:16789")
	for {
		wg.Add(1)
		go read(listen, ch, addrch)
		wg.Add(1)
		go forward(listen, dstAddr, ch)
		fmt.Println("thread = ", runtime.NumGoroutine())
		go backward(handle, listen, addrch)
		wg.Wait()
	}

}
