package ldap

import (
	"context"
	"net"

	"github.com/honeytrap/honeytrap/event"
	"github.com/honeytrap/honeytrap/pushers"
	"github.com/honeytrap/honeytrap/services"
	logging "github.com/op/go-logging"
)

var (
	_   = services.Register("ldap", LDAP)
	log = logging.MustGetLogger("services/ldap")
)

func LDAP(options ...services.ServicerFunc) services.Servicer {

	s := &ldapService{
		msg: make(chan htLog),
	}

	for _, o := range options {
		o(s)
	}

	return s
}

type ldapService struct {
	msg chan Message

	c pushers.Channel
}

func (s *ldapService) SetChannel(c pushers.Channel) {

	s.c = c
}

func (s *ldapService) Handle(ctx context.Context, conn net.Conn) error {

	c, err := NewConn(conn, s.msg)
	if err != nil {
		return err
	}

	go func() {
		for {
			select {
			case msg := <-s.msg:
				s.c.Send(event.New(
					services.EventOptions,
					event.Category("ldap"),
					event.SourceAddr(conn.RemoteAddr()),
					event.DestinationAddr(conn.LocalAddr()),
					event.Custom("ldap.id", msg.cmd),
					event.Custom("ldap.operation", msg.protocolOp),
				))
			}
		}
	}()

	return c.Serve()
}
