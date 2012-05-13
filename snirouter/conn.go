package snirouter

import (
	"errors"
	"io"
	"fmt"
	"net"
	"strings"
)

type Conn struct {
	net.Conn
	// Data to be replayed stashed here
	InitialData []byte
	ServerName string
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if len(c.InitialData) > 0 {
		n = copy(b, c.InitialData)
		c.InitialData = []byte{}
	} else {
		return c.Conn.Read(b)
	}
	return
}

var errBackendClosed = errors.New("backend connection closed")
var errClientClosed	 = errors.New("client connection closed")

type finishedConn struct {
	Direction        int
	BytesTransferred int64
	Error            error
}

func JoinConns(in net.Conn, out net.Conn) (inBytes int64, outBytes int64) {
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
			if fc.Error != nil && !outdone {
				fmt.Printf("Actual error on %d: %d bytes read, %s\n", fc.Direction, fc.BytesTransferred, fc.Error.Error())
			}
			fmt.Printf("inbound done: %d bytes\n", fc.BytesTransferred)
			out.Close()
			indone = true
			inBytes = fc.BytesTransferred
		case 1:
			if fc.Error != nil && !indone {
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

func connCopy(from net.Conn, to net.Conn, ch chan finishedConn, dir int) {
	data := make([]byte, 1024)
	var err error
	var n int64
	done := false

	for !done {
		nr, er := from.Read(data)
		switch er {
		case nil:
			nw, ew := to.Write(data[0:nr])
			if nw > 0 {
				n += int64(nw)
			}
			if ew != nil {
				err = ew
				done = true
				break
			}
		case io.EOF:
			if dir == 0 {
				err = errClientClosed
				done = true
				break
			} else {
				nw, ew := to.Write(data[0:nr])
				if nw > 0 {
					n += int64(nw)
				}
				if ew != nil {
					err = ew
				}
				done = true
				break
			}
		default:
			if strings.HasSuffix(er.Error(), "use of closed network connection") {
				switch dir {
				case 0:
					err = errClientClosed
				case 1:
					err = errBackendClosed
				}
			} else {
				err = er
			}
			done = true
			break
		}
	}

	ch <- finishedConn{dir, n, err}
}
