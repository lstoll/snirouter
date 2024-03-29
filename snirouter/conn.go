package snirouter

import (
	"net"
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
