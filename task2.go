package main

import (
	"fmt"
	"unsafe"
)

// Define the process name to match
const processName = "myprocess"

// Define the specific TCP port to allow (default 4040)
const allowedPort = 4040

// etherHdr represents the Ethernet header.
type etherHdr struct {
	// Add fields as needed
}

// ipHdr represents the IP header.
type ipHdr struct {
	// Add fields as needed
}

// tcpHdr represents the TCP header.
type tcpHdr struct {
	// Add fields as needed
}

// Constants for IP protocol
const (
	IPPROTO_TCP = 6
)

// Constants for XDP actions
const (
	XDP_PASS = 1
	XDP_DROP = 2
)

// filterTCP checks if the packet is TCP and matches the process name.
func filterTCP(skb []byte) int {
	eth := (*etherHdr)(unsafe.Pointer(&skb[0]))
	ip := (*ipHdr)(unsafe.Pointer(&skb[eth.hlen()]))
	tcp := (*tcpHdr)(unsafe.Pointer(&skb[eth.hlen()+int(ip.len())]))

	if ip.protocol == IPPROTO_TCP &&
		loadBytes(skb, tcp.source, allowedPort) == 0 &&
		loadBytes(skb, tcp.dest, allowedPort) == 0 {

		// Allow traffic to the specific port
		return XDP_PASS
	}

	// Drop all other traffic for the process
	return XDP_DROP
}

// loadBytes loads bytes from the packet.
func loadBytes(skb []byte, offset int, value int) int {
	var buf [4]byte
	*(*int)(unsafe.Pointer(&buf[0])) = value
	for i := 0; i < 4; i++ {
		if skb[offset+i] != buf[i] {
			return -1
		}
	}
	return 0
}

func main() {
	// Simulated packet data
	skb := make([]byte, 1500)
	result := filterTCP(skb)
	fmt.Println("Result:", result)
}
