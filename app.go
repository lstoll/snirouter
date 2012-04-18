package main

import (
	"fmt"
	"net"
	"os"
	"snirouter/snirouter"
)

func main() {
	var (
		host   = "127.0.0.1"
		port   = "9998"
		remote = host + ":" + port
		data   = make([]byte, 1024)
	)
	fmt.Println("Initiating server... (Ctrl-C to stop)")

	lis, error := net.Listen("tcp", remote)
	defer lis.Close()
	if error != nil {
		fmt.Printf("Error creating listener: %s\n", error)
		os.Exit(1)
	}
	for {
		var read = true
		underConn, error := lis.Accept()
		conn := snirouter.Conn{underConn}
		if error != nil {
			fmt.Printf("Error: Accepting data: %s\n", error)
			os.Exit(2)
		}
		fmt.Printf("=== New Connection received from: %s \n", conn.RemoteAddr())
		for read {
			n, error := conn.Read(data)
			switch error {
			case nil:
				fmt.Println(string(data[0:n])) // Debug
				//response = response + string(data[0:n])
			default:
				fmt.Printf("Error: Reading data : %s \n", error)
				read = false
			}
		}
		conn.Close()
	}

}
