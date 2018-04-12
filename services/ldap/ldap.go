package ldap

import (
	"bufio"
	"context"
	"fmt"
	"net"

	"github.com/honeytrap/honeytrap/event"
	"github.com/honeytrap/honeytrap/pushers"
	"github.com/honeytrap/honeytrap/services"
	ber "github.com/honeytrap/honeytrap/services/asn1-ber"
	logging "github.com/op/go-logging"
)

var (
	_   = services.Register("ldap", LDAP)
	log = logging.MustGetLogger("services/ldap")
)

// LDAP service setup
func LDAP(options ...services.ServicerFunc) services.Servicer {

	s := &ldapService{
		m: make(chan *Message, 1),
	}

	for _, o := range options {
		if err := o(s); err != nil {
			log.Warning(err.Error())
		}
	}

	return s
}

type ldapService struct {
	m chan *Message

	c pushers.Channel
}

func (s *ldapService) SetChannel(c pushers.Channel) {

	s.c = c
}

func (s *ldapService) Handle(ctx context.Context, conn net.Conn) error {

	br := bufio.NewReader(conn)

	c := NewConn(conn)

	go func() {
		for {
			select {
			case msg := <-s.m:
				op, ok := appCodes[msg.protocolOp]
				if !ok {
					op = fmt.Sprint(msg.protocolOp)
				}
				s.c.Send(event.New(
					services.EventOptions,
					event.Category("ldap"),
					event.SourceAddr(conn.RemoteAddr()),
					event.DestinationAddr(conn.LocalAddr()),
					event.Custom("ldap.id", msg.id),
					event.Custom("ldap.operation", op),
					event.CopyFrom(msg.log),
				))
			}
		}
	}()

	for {

		packet, err := ber.ReadPacket(br)
		if err != nil {
			return err
		}

		// Decode an ASN.1 packet into a Message
		m, err := NewMessage(packet)
		if err != nil {
			return err
		}

		// Send Message for logging.
		s.m <- m

		// Close the connection if unbind is requested
		if m.protocolOp == ApplicationUnbindRequest || m.protocolOp == ApplicationAbandonRequest {
			// Cleanup pending operatons if neccesary
			return nil
		}

		// Handle request and create a response packet(ASN.1)
		p, err := m.Response(c.authState)
		if err != nil {
			return err
		}

		// Write the response
		if err := c.Write(p.Bytes()); err != nil {
			return err
		}

	}

	//return nil
}
