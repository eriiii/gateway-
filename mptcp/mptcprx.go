package main

import (
	"context"
	_ "encoding/hex"
	"fmt"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/pcap"
)

// recerive packet from client gateway
func read(listen net.Conn, ch chan []byte) {
	defer wg.Done()
	for {
		buf := make([]byte, 2048)
		n, err := listen.Read(buf[:])
		fmt.Println("read packet")
		if err != nil {
			fmt.Println("tcp read err = ", err)
			continue
		}
		//getting ethernet payload out from packet
		ch <- buf[:n]
		fmt.Println("packet save ")
	}
}

func forward(listen *net.UDPConn, addr *net.UDPAddr, ch chan []byte) {
	defer wg.Done()
	//1024 byte data, some packet is not able to decoded correctly, for testing, transfer 1024 byte data instead
	data := []byte{1, 39, 121, 0, 1, 63, 161, 0, 0, 0, 4, 4, 223, 249, 48, 227, 90, 100, 141, 77, 221, 150, 9, 148, 158, 52, 89, 17, 185, 231, 162, 225, 169, 254, 58, 61, 87, 253, 11, 24, 61, 196, 166, 54, 21, 198, 37, 136, 158, 12, 78, 152, 71, 12, 189, 210, 167, 243, 186, 149, 33, 131, 91, 109, 196, 241, 80, 22, 27, 56, 154, 117, 129, 75, 206, 53, 126, 35, 13, 163, 139, 227, 109, 5, 37, 15, 120, 137, 65, 235, 76, 50, 142, 59, 250, 72, 43, 228, 3, 81, 215, 5, 226, 17, 171, 230, 92, 110, 213, 202, 158, 27, 106, 144, 247, 99, 197, 147, 211, 151, 25, 50, 101, 27, 102, 16, 19, 191, 215, 103, 134, 32, 228, 38, 198, 229, 141, 195, 178, 131, 195, 44, 227, 106, 102, 211, 124, 186, 28, 133, 94, 157, 231, 38, 78, 212, 72, 21, 201, 110, 152, 57, 161, 113, 15, 184, 101, 19, 57, 185, 29, 182, 205, 250, 123, 136, 43, 70, 144, 234, 46, 133, 112, 232, 125, 200, 95, 159, 174, 217, 222, 146, 7, 225, 229, 171, 81, 199, 239, 222, 72, 189, 74, 90, 195, 248, 42, 160, 103, 43, 114, 21, 113, 205, 84, 42, 63, 32, 114, 175, 28, 175, 192, 43, 80, 81, 196, 13, 159, 126, 174, 193, 112, 118, 39, 50, 195, 168, 235, 223, 56, 28, 227, 86, 155, 94, 206, 192, 45, 161, 151, 178, 247, 209, 167, 133, 244, 170, 172, 227, 94, 26, 253, 204, 179, 204, 140, 81, 187, 94, 31, 48, 210, 68, 129, 158, 52, 53, 65, 200, 156, 218, 95, 142, 24, 232, 189, 232, 73, 201, 133, 189, 116, 99, 225, 24, 94, 47, 82, 131, 173, 171, 182, 78, 4, 27, 123, 11, 49, 13, 121, 135, 26, 54, 181, 122, 8, 102, 43, 241, 34, 47, 188, 46, 88, 203, 206, 234, 158, 237, 217, 133, 64, 205, 90, 26, 243, 174, 175, 171, 251, 56, 119, 13, 210, 8, 241, 112, 63, 187, 75, 39, 253, 179, 41, 96, 60, 237, 215, 253, 112, 53, 171, 209, 161, 212, 173, 5, 42, 99, 58, 175, 192, 121, 145, 180, 232, 177, 48, 213, 235, 101, 125, 52, 78, 213, 114, 138, 67, 69, 157, 255, 39, 3, 155, 44, 140, 44, 62, 234, 187, 183, 165, 55, 107, 32, 75, 134, 174, 185, 26, 185, 147, 162, 251, 14, 150, 135, 60, 29, 200, 42, 76, 236, 229, 141, 22, 127, 104, 81, 152, 49, 76, 235, 178, 218, 136, 33, 238, 27, 216, 67, 19, 17, 112, 248, 137, 15, 205, 194, 71, 131, 53, 19, 164, 235, 219, 117, 62, 92, 98, 12, 50, 82, 205, 239, 115, 55, 246, 54, 127, 52, 104, 157, 144, 178, 197, 48, 203, 165, 33, 251, 158, 58, 75, 11, 219, 77, 122, 104, 80, 142, 176, 94, 127, 149, 188, 22, 59, 171, 71, 12, 18, 25, 173, 231, 77, 214, 249, 220, 159, 56, 43, 112, 114, 49, 250, 239, 74, 40, 255, 123, 45, 52, 195, 174, 224, 90, 237, 57, 11, 157, 118, 215, 197, 207, 203, 103, 10, 205, 61, 108, 12, 10, 91, 104, 64, 244, 29, 119, 230, 251, 58, 146, 160, 158, 255, 97, 179, 39, 45, 184, 164, 236, 33, 30, 14, 81, 41, 195, 29, 192, 104, 187, 231, 7, 63, 170, 118, 65, 145, 226, 11, 129, 101, 127, 76, 129, 178, 32, 32, 188, 31, 40, 148, 73, 142, 69, 180, 152, 83, 101, 211, 243, 6, 136, 115, 139, 209, 27, 233, 121, 134, 6, 32, 99, 67, 202, 6, 111, 100, 31, 243, 37, 7, 80, 218, 222, 60, 95, 175, 187, 15, 0, 127, 21, 194, 133, 169, 232, 222, 228, 202, 80, 30, 201, 134, 175, 129, 194, 84, 218, 115, 214, 253, 243, 22, 5, 59, 64, 197, 12, 137, 141, 171, 252, 13, 229, 1, 217, 30, 226, 137, 238, 29, 68, 146, 121, 10, 97, 131, 160, 97, 3, 145, 148, 199, 166, 243, 218, 65, 150, 202, 94, 112, 43, 220, 75, 106, 138, 197, 167, 167, 255, 140, 77, 139, 78, 197, 245, 206, 46, 18, 19, 140, 178, 103, 197, 134, 156, 116, 147, 217, 63, 169, 235, 228, 203, 245, 122, 150, 155, 212, 112, 19, 70, 134, 214, 155, 10, 111, 52, 182, 116, 33, 95, 41, 54, 36, 11, 163, 111, 231, 68, 152, 100, 22, 128, 226, 66, 26, 158, 99, 154, 133, 66, 81, 183, 111, 127, 221, 208, 66, 128, 146, 224, 143, 16, 43, 88, 11, 254, 123, 64, 252, 184, 82, 72, 73, 226, 63, 200, 134, 225, 202, 225, 252, 215, 100, 198, 226, 35, 206, 183, 8, 4, 175, 89, 151, 42, 134, 60, 202, 49, 2, 72, 219, 201, 147, 200, 167, 48, 123, 58, 197, 61, 52, 30, 140, 44, 170, 253, 49, 12, 131, 88, 8, 185, 156, 184, 168, 250, 138, 178, 100, 123, 38, 238, 25, 196, 114, 129, 109, 33, 179, 83, 31, 242, 25, 9, 75, 142, 145, 188, 161, 218, 149, 218, 134, 102, 96, 246, 245, 43, 82, 38, 14, 142, 61, 162, 215, 127, 221, 6, 103, 26, 149, 189, 36, 112, 230, 129, 209, 141, 141, 52, 232, 56, 18, 115, 218, 151, 240, 16, 218, 233, 19, 131, 87, 64, 43, 181, 240, 224, 254, 131, 176, 81, 120, 28, 175, 199, 224, 245, 247, 84, 49, 19, 145, 208, 107, 0, 187, 171, 109, 243, 95, 233, 91, 136, 225, 132, 104, 220, 73, 187, 142, 220, 96, 133, 184, 205, 137, 152, 131, 251, 197, 213, 245, 236, 208, 147, 79, 185, 143, 230, 27, 31, 136, 86, 213, 137, 218, 5, 238, 87, 75, 122, 64, 165, 39, 138, 249, 3, 213, 226, 174, 96, 219, 66, 201, 158, 35, 250, 27, 141, 237, 27, 133, 119, 121, 204, 210, 127, 21, 125, 76, 216, 235, 64, 87, 144, 241, 215, 218, 76, 4, 94, 129, 54, 181, 86, 196}
	for {
		fmt.Println("sending channel length = ", len(ch))
		buffer := <-ch
		//taking the ethernet payload and decoding, making it new packet
		packet := gopacket.NewPacket(buffer, layers.LayerTypeIPv4, gopacket.Default)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if ipLayer != nil && udpLayer != nil {
			ip := ipLayer.(*layers.IPv4)
			udp := udpLayer.(*layers.UDP)
			//show client ip address, des address, data length of packey
			fmt.Println(ip.SrcIP, ip.DstIP, udp.SrcPort)
			fmt.Println("receive packet")
			fmt.Println(gopacket.Payload(packet.ApplicationLayer().Payload()))
			//send packet to server using udp
			_, err := listen.WriteToUDP(packet.ApplicationLayer().Payload(), addr)
			if err != nil {
				fmt.Println("sending err = ", err)
				return
			} else {
				fmt.Println("packet forward")
			}
		} else if ipLayer == nil {
			_, err := listen.WriteToUDP(data, addr)
			if err != nil {
				fmt.Println("sending err = ", err)
				return
			} else {
				fmt.Println("packet forward")
			}
			fmt.Println("iplayer nil")
			fmt.Println()
		} else if udpLayer == nil {
			_, err := listen.WriteToUDP(data, addr)
			if err != nil {
				fmt.Println("sending err = ", err)
				return
			} else {
				fmt.Println("packet forward")
			}
			fmt.Println("udplayer nil")
			//fmt.Println(hex.EncodeToString(buffer))
			fmt.Println()
		}

	}

}

var wg sync.WaitGroup

func main() {
	ch := make(chan []byte, 256)

	//enablke MPTCP
	var lc net.ListenConfig
	lc.SetMultipathTCP(true)

	//one of the server gateway ip address
	listen1, err := lc.Listen(context.Background(), "tcp", "192.168.0.199:14567")
	if err != nil {
		fmt.Println("listen tcp err = ", err)
		return
	}

	conn1, err := listen1.Accept()
	if err != nil {
		fmt.Println("listen err = ", err)
		return
	}

	//open socket, server gateway ip address
	udpconn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv4(192, 168, 0, 199),
		Port: 14570,
	})
	if err != nil {
		fmt.Println("open udp socket error")
	}

	//server ip address
	dstAddr, _ := net.ResolveUDPAddr("udp", "192.168.0.116:16789")

	for {
		wg.Add(1)
		go read(conn1, ch)
		wg.Add(1)
		go forward(udpconn, dstAddr, ch)
		//fmt.Println("thread = ", runtime.NumGoroutine())
		wg.Wait()
	}

}
