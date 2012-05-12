package main

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"snirouter/snirouter"
	"strings"
)

func readInt16BE(data []byte, pos int) int {
	return int(binary.BigEndian.Uint16(data[pos : pos+2]))
}

/**
* Gets the SNI header. Returns the host if set, or an empty string, and a 'clean' connection to start TLS on
 */
func getSNI(underConn net.Conn) *snirouter.Conn {
	var (
		data      = make([]byte, 1024)
		sniHeader = ""
	)
	// var conn(net.Conn)

	/* Read the SNI shizz
	This is all thanks to https://github.com/axiak/filternet - lib/sniparse.js */
	readLen, _ := underConn.Read(data)
	// Check if it's a TLS connection
	if data[0] != 22 {
		// Not TLS handshake. Replay conn, pass through.
		return &snirouter.Conn{underConn, data[0:readLen], ""}
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

	return &snirouter.Conn{underConn, data[0:readLen], sniHeader}
}

func handleConn(underConn net.Conn) {
	var (
		certfile = ""
		keyfile  = ""
	)
	defer underConn.Close()

	fmt.Printf("=== New Connection received from: %s \n", underConn.RemoteAddr())

	// get the SNI host and replace the conn
	conn := getSNI(underConn)
	defer conn.Close()

	if conn.ServerName != "" {
		fmt.Printf("=== Incoming connection for %s\n", conn.ServerName)
	} else {
		fmt.Println("=== No SNI header specified")
	}

	// TODO - this is where the magic cert lookup goes.
	if conn.ServerName == "test.com" {
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
	defer tlsconn.Close()

	fmt.Println("=== Created TLS Server")

	// Open upstream connection
	upconn, err := net.Dial("tcp", "localhost:9997")
	if err != nil {
		panic(fmt.Errorf("Error opening upstream conn: %v", err))
	}

	in, out := joinConns(tlsconn, upconn)
	fmt.Printf("=== Closing Connections after: %d inbound, %d outbound bytes\n", in, out)
	return
}

type finishedConn struct {
	Direction        int
	BytesTransferred int64
	Error            error
}

func connCopy(from net.Conn, to net.Conn, ch chan finishedConn, dir int) {
	n, err := io.Copy(to, from)
	if err == io.EOF {
		err = nil
	}
	ch <- finishedConn{dir, n, err}
}

func joinConns(in net.Conn, out net.Conn) (inBytes int64, outBytes int64) {
	cfin := make(chan finishedConn, 2)
	defer close(cfin)

	go connCopy(in, out, cfin, 0)
	go connCopy(out, in, cfin, 1)

	indone := false
	outdone := false

	for !(outdone && indone) {
		fc := <-cfin
		switch fc.Direction {
		case 0:
			if fc.Error != nil && !strings.HasSuffix(fc.Error.Error(), "use of closed network connection") {
				fmt.Printf("Actual error on %d: %d bytes read, %s\n", fc.Direction, fc.BytesTransferred, fc.Error.Error())
			}
			fmt.Printf("inbound done: %d bytes\n", fc.BytesTransferred)
			out.Close()
			indone = true
			inBytes = fc.BytesTransferred
		case 1:
			if fc.Error != nil && !strings.HasSuffix(fc.Error.Error(), "use of closed network connection") {
				fmt.Printf("Actual error on %d: %d bytes read, %s\n", fc.Direction, fc.BytesTransferred, fc.Error.Error())
			}
			fmt.Printf("outbound done: %d bytes\n", fc.BytesTransferred)
			outdone = true
			outBytes = fc.BytesTransferred
			in.Close()
		}
	}
	return
}

func main() {
	var (
		host   = "127.0.0.1"
		port   = "9998"
		remote = host + ":" + port
	)
	fmt.Println("Initiating server on port 9998... (Ctrl-C to stop)")

	lis, err := net.Listen("tcp", remote)
	defer lis.Close()
	if err != nil {
		fmt.Printf("Error creating listener: %s\n", err)
		os.Exit(1)
	}
	for {
		underConn, err := lis.Accept()
		if err != nil {
			fmt.Printf("Error: Accepting data: %s\n", err)
			os.Exit(2)
		}

		go handleConn(underConn)
	}
}
