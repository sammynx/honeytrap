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

// NewConn create a new LDAP connection
func NewConn(c net.Conn) *Conn {
	return &Conn{
		conn:      c,
		authState: AuthAnonymous,
	}
}
