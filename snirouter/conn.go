package snirouter

import (
	"net"
	// "time"
)

type Conn struct {
	net.Conn
	// the underlying connection
	// Conn net.Conn
	InitialData []byte
}

/* For now, these just pass through - but they are where we do the magic. */

func (c *Conn) Read(b []byte) (n int, err error) {
	if len(c.InitialData) > 0 {
		n = copy(b, c.InitialData)
		c.InitialData = []byte{}
	} else {
		return c.Conn.Read(b)
	}
	return
}

func (c *Conn) SetInitialData(b []byte) {
	c.InitialData = b
}

/* Pretty sure I don't need these - it will do it itself. */

// func (c *Conn) Write(b []byte) (int, error) {
// 	return c.Conn.Write(b)
// }

// /* These all just pass straight through to the underlying connection */
// func (c *Conn) LocalAddr() net.Addr {
// 	return c.Conn.LocalAddr()
// }

// func (c *Conn) RemoteAddr() net.Addr {
// 	return c.Conn.RemoteAddr()
// }

// func (c *Conn) SetDeadline(t time.Time) error {
// 	return c.Conn.SetDeadline(t)
// }

// func (c *Conn) SetReadDeadline(t time.Time) error {
// 	return c.Conn.SetReadDeadline(t)
// }

// func (c *Conn) SetWriteDeadline(t time.Time) error {
// 	return c.Conn.SetWriteDeadline(t)
// }

// func (c *Conn) Close() error {
// 	return c.Conn.Close()
// }
