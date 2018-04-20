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

	s := &ldapService{}

	for _, o := range options {
		if err := o(s); err != nil {
			log.Warning(err.Error())
		}
	}

	return s
}

type ldapService struct {
	c pushers.Channel
}

func (s *ldapService) SetChannel(c pushers.Channel) {

	s.c = c
}

func (s *ldapService) Handle(ctx context.Context, conn net.Conn) error {

	br := bufio.NewReader(conn)

	c := NewConn(conn)

	for {

		if err := c.Read(br); err != nil {
			return err
		}

		// Send Message for logging.
		s.c.Send(event.New(
			services.EventOptions,
			event.Category("ldap"),
			event.SourceAddr(conn.RemoteAddr()),
			event.DestinationAddr(conn.LocalAddr()),
			event.CopyFrom(c.msg.log),
		))

		// Close the connection if unbind is requested
		if c.msg.protocolOp == ApplicationUnbindRequest || c.msg.protocolOp == ApplicationAbandonRequest {
			// Cleanup pending operatons if necessary
			return nil
		}

		// Handle request and create a response packet(ASN.1)
		p, err := c.msg.Response(c.authState)
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
