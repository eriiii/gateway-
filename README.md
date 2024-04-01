# gateway-
TX means client gateway, RX means server gateway
change the ip address and interface name, and then it can work

For testing, client send UDP packet with 1024 bytes.
If want to capture TCP packet, change the client gateway func "capturesend" udplayer to tcplayer, and limit tcp packet length..
