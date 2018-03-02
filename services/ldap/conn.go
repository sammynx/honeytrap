package ldap

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"net"
)

type Conn struct {
	conn net.Conn
	msg  chan Message
}

func NewConn(conn net.Conn, msg chan Message) (*Conn, error) {
	c := &Conn{
		conn: conn,
		msg:  msg,
	}

	return c, nil
}

func (c *Conn) Serve() error {
	br := bufio.NewReader(c.conn)
	r := ioutil.ReadAll(br)

	m, err := NewMessage(r)

	//Send ldap request to log
	c.msg <- m

	resp, err := m.Response()

	bw := bufio.NewWriter(c.conn)
	ar := bytes.NewReader(resp)

	_, err = ar.WriteTo(bw)

	return err
}
