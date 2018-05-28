package ldap

import (
	"io"
	"net"

	ber "github.com/asn1-ber"
)

// Conn is a connection object for an LDAP session
type Conn struct {
	conn   net.Conn
	packet *ber.Packet
	auth   Authenticator
}

// NewConn create a new LDAP connection
func NewConn(c net.Conn, a Authenticator) *Conn {
	return &Conn{
		conn: c,
		auth: a,
	}
}

func (c *Conn) Read(r io.Reader) error {

	p, err := ber.ReadPacket(r)
	if err != nil {
		return err
	}

	c.packet = p

	return nil
}

// Auth: authenticates a user with a password.
// if authentication fails, AuthAnonymous is set.
func (c *Conn) Auth(user, passwd string) {

}
