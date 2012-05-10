package main

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
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
	conn := snirouter.Conn{underConn, []byte{}}

	/* Read the SNI shizz
	This is all thanks to https://github.com/axiak/filternet - lib/sniparse.js */
	readLen, _ := conn.Read(data)
	// Check if it's a TLS connection
	if data[0] != 22 {
		// Not TLS handshake. Replay conn, pass through.
		conn.SetInitialData(data[0:readLen])
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
		} else {
			// TODO - there's still some weirdness here - need to figure structure better.
			// For now, just break out if the first header isn't us
			break
			// currentPos += 4 + readInt16BE(data, currentPos+2)
		}

	}
	conn.SetInitialData(data[0:readLen])

	return sniHeader, &conn
}

func handleConn(underConn net.Conn, err error) {
	var (
		certfile = ""
		keyfile  = ""
	)

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

	// TODO - this is where the magic cert lookup goes.
	if sniHost == "test.com" {
		certfile = "certs/test.com.crt"
		keyfile = "certs/test.com.key"
	} else {
		certfile = "certs/unknown.com.crt"
		keyfile = "certs/unknown.com.key"
	}

	cert, _ := tls.LoadX509KeyPair(certfile, keyfile)
	config := tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	tlsconn := tls.Server(conn, &config)

	fmt.Println("=== Created TLS Server")

	var read = true
	var data = make([]byte, 1024)

	// Open upstream connection
	upconn, err := net.Dial("tcp", "localhost:9997")

	for read {
		n, error := tlsconn.Read(data)
		switch error {
		case nil:
			upconn.Write(data[0:n])
		case io.EOF:
			read = false
		default:
			fmt.Printf("Error: Reading data : %s \n", error)
			read = false
		}
	}
	fmt.Println("=== Closing Connections")
	upconn.Close()
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
		go handleConn(underConn, error)

	}

}
