package ldap

import (
	"net"
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
	authState int
}

// Return a new connection
func NewConn(c net.Conn) *Conn {
	return &Conn{
		conn:      c,
		authState: AuthAnonymous,
	}
}

func (c *Conn) Write(b []byte) error {
	if _, err := c.conn.Write(b); err != nil {
		return err
	}

	return nil
}
