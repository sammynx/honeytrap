package ldap

import (
	"net"

	ber "github.com/honeytrap/honeytrap/services/asn1-ber"
)

const (
	AuthAnonymous = iota
	AuthUser
	AuthAdmin
)

type Conn struct {
	conn      net.Conn
	msg       *Message
	authState int
}

func NewConn(c net.Conn) *Conn {
	return &Conn{
		conn:      c,
		authState: AuthAnonymous,
	}
}

func (c *Conn) NewMessage(p *ber.Packet) {
	c.msg = &Message{
		id:         int(p.Children[0].Value.(int64)),
		protocolOp: int(p.Children[1].Tag),
	}
}

func (c *Conn) Write(b []byte) error {
	if _, err := c.conn.Write(b); err != nil {
		return err
	}

	return nil
}
