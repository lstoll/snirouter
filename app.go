package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"snirouter/snirouter"
)

func readInt16BE(data []byte, pos int) int {
	return int(binary.BigEndian.Uint16(data[pos : pos+2]))
}

/**
* Gets the SNI header. Returns the host if set, or an empty string, and a 'clean' connection to start TLS on
 */
func getSNI(underConn net.Conn) (string, *snirouter.Conn) {
	var (
		data      = make([]byte, 1024)
		sniHeader = ""
	)
	// var conn(net.Conn)
	conn := snirouter.Conn{underConn}

	/* Read the SNI shizz
	This is all thanks to https://github.com/axiak/filternet - lib/sniparse.js */
	conn.Read(data)
	// Check if it's a TLS connection
	if data[0] != 22 {
		// Not TLS handshake. Replay conn, pass through.
		// TODO conn.replay data ?
		return "", &conn
	}

	// Session ID length
	currentPos := 43
	// skip Session IDs
	currentPos += 1 + int(data[currentPos])
	// skip cipher suites
	currentPos += 2 + readInt16BE(data, currentPos)
	// skip compression methods
	currentPos += 1 + int(data[currentPos])
	// skip extensions length
	currentPos += 2

	for currentPos < len(data) {
		if readInt16BE(data, currentPos) == 0 {
			sniLength := readInt16BE(data, currentPos+2)
			currentPos += 4
			if data[currentPos] != 0 {
				// RFC says this is a reserved host type, not DNS.
			}
			currentPos += 5
			sniHeader = string(data[currentPos:(currentPos + sniLength - 5)])
			break
		}
	}

	// TODO conn.reset data?
	return sniHeader, &conn

}

func handleConn(underConn net.Conn, err error) {
	if err != nil {
		fmt.Printf("Error: Accepting data: %s\n", err)
		os.Exit(2)
	}
	fmt.Printf("=== New Connection received from: %s \n", underConn.RemoteAddr())

	// get the SNI host and replace the conn
	sniHost, conn := getSNI(underConn)

	if sniHost != "" {
		fmt.Printf("=== Incoming connection for %s\n", sniHost)
	} else {
		fmt.Println("=== No SNI header specified")
	}

	// var read = true

	/*for read {
		n, error := conn.Read(data)
		switch error {
		case nil:
			fmt.Println(string(data[0:n])) // Debug
			//response = response + string(data[0:n])
		default:
			fmt.Printf("Error: Reading data : %s \n", error)
			read = false
		}
	}*/
	fmt.Println("=== Closing Connection")
	conn.Close()
}

func main() {
	var (
		host   = "127.0.0.1"
		port   = "9998"
		remote = host + ":" + port
	)
	fmt.Println("Initiating server on port 9998... (Ctrl-C to stop)")

	lis, error := net.Listen("tcp", remote)
	defer lis.Close()
	if error != nil {
		fmt.Printf("Error creating listener: %s\n", error)
		os.Exit(1)
	}
	for {

		underConn, error := lis.Accept()
		if error != nil {
			fmt.Printf("Error: Accepting data: %s\n", error)
			os.Exit(2)
		}
		fmt.Printf("=== New Connection received from: %s \n", underConn.RemoteAddr())

		// get the SNI host and replace the conn
		sniHost, conn := getSNI(underConn)

		if sniHost != "" {
			fmt.Printf("=== Incoming connection for %s\n", sniHost)
		} else {
			fmt.Println("=== No SNI header specified")
		}

		// var read = true

		/*for read {
			n, error := conn.Read(data)
			switch error {
			case nil:
				fmt.Println(string(data[0:n])) // Debug
				//response = response + string(data[0:n])
			default:
				fmt.Printf("Error: Reading data : %s \n", error)
				read = false
			}
		}*/
		fmt.Println("=== Closing Connection")
		conn.Close()
	}

}
