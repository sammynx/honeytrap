package ldap

import (
	"io"
	"net"

	ber "github.com/asn1-ber"
)

// Authentication states
const (
	AuthAnonymous = iota
	AuthUser
	AuthAdmin
)

// Conn is a connection object for an LDAP session
type Conn struct {
	conn      net.Conn
	msg       *Message
	authState int
}

// NewConn create a new LDAP connection
func NewConn(c net.Conn) *Conn {
	return &Conn{
		conn:      c,
		authState: AuthAnonymous,
	}
}

func (c *Conn) Read(r io.Reader) error {

	packet, err := ber.ReadPacket(r)
	if err != nil {
		return err
	}

	ber.PrintPacket(packet)

	// Decode an ASN.1 packet into a Message
	if c.msg, err = NewMessage(packet); err != nil {
		return err
	}

	return nil
}
