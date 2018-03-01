package ldap

import (
	"bufio"
	"net"
)

type Conn struct {
	conn net.Conn
	br   *bufio.Reader
	bw   *bufio.Writer
	msg  chan htLog
}

func NewConn(conn net.Conn, msg chan htLog) (*Conn, error) {
	c := &Conn{
		conn: conn,
		br:   bufio.NewReader(conn),
		bw:   bufio.NewWriter(conn),
		msg:  msg,
	}

	return c, nil
}

func (c *Conn) Serve() error {
	return nil
}
