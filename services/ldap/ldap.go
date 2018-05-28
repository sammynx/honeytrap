package ldap

import (
	"bufio"
	"context"
	"net"

	ber "github.com/asn1-ber"
	"github.com/honeytrap/honeytrap/event"
	"github.com/honeytrap/honeytrap/pushers"
	"github.com/honeytrap/honeytrap/services"
	logging "github.com/op/go-logging"
)

var (
	_   = services.Register("ldap", LDAP)
	log = logging.MustGetLogger("services/ldap")
)

// LDAP service setup
func LDAP(options ...services.ServicerFunc) services.Servicer {

	s := &ldapService{
		Users: [][]string{[]string{"admin", "admin"}},
	}

	for _, o := range options {
		if err := o(s); err != nil {
			log.Warning(err.Error())
		}
	}

	s.a = NewAuth(s.Users)

	return s
}

type ldapService struct {
	c pushers.Channel

	a Authenticator

	Users [][]string `toml:"users"`
}

func (s *ldapService) SetChannel(c pushers.Channel) {

	s.c = c
}

func (s *ldapService) Handle(ctx context.Context, conn net.Conn) error {

	br := bufio.NewReader(conn)

	c := NewConn(conn, s.a)

	for {

		if err := c.Read(br); err != nil {
			return err
		}

		m, err := NewMessage(c)
		if err != nil {
			return err
		}

		// Send Message for logging.
		s.c.Send(event.New(
			services.EventOptions,
			event.Category("ldap"),
			event.SourceAddr(conn.RemoteAddr()),
			event.DestinationAddr(conn.LocalAddr()),
			event.CopyFrom(m.log),
		))

		// Close the connection if unbind is requested
		if m.protocolOp == ApplicationUnbindRequest || m.protocolOp == ApplicationAbandonRequest {
			// Cleanup pending operatons if necessary
			return nil
		}

		// Handle request and create a response packet(ASN.1)
		p, err := m.Response(c.authState)
		if err != nil {
			return err
		}

		ber.PrintPacket(p)

		// Write the response
		if _, err := c.conn.Write(p.Bytes()); err != nil {
			return err
		}

	}
}
