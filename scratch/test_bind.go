package main

import (
	"fmt"
	"net"
)

func main() {
	c1, err := net.ListenPacket("udp", "127.0.0.1:18180")
	if err != nil {
		fmt.Println("c1:", err)
	} else {
		fmt.Println("c1 ok")
		defer c1.Close()
	}

	c2, err := net.ListenPacket("udp", "0.0.0.0:18180")
	if err != nil {
		fmt.Println("c2:", err)
	} else {
		fmt.Println("c2 ok")
		defer c2.Close()
	}
}
