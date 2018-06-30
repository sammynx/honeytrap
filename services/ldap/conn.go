package ldap

import (
	"bufio"
	"net"
)

type Conn struct {
	conn       net.Conn
	ConnReader *bufio.Reader
	ConnWriter *bufio.Writer
}

func NewConn(c net.Conn) *Conn {
	return &Conn{
		conn:       c,
		ConnReader: bufio.NewReader(c),
		ConnWriter: bufio.NewWriter(c),
	}
}
