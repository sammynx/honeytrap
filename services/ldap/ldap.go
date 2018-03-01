package ldap

import (
	"bufio"
	"context"
	"io"
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

type htLog struct {
	cmd, param string
}

type ldapService struct {
	msg chan htLog

	c pushers.Channel
}

func (s *ldapService) SetChannel(c pushers.Channel) {

	s.c = c
}

func (s *ldapService) Handle(ctx context.Context, conn net.Conn) error {

	br := bufio.NewReader(conn)
	//tp := textproto.NewReader(br)

	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				log.Debugf("EOF, size %d, bytes %v", len(line), line)
				return nil
			}

			return err
		}

		log.Debugf("size %d, bytes %v", len(line), line)
	}

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
					event.Custom("ldap.cmd", msg.cmd),
					event.Custom("ldap.param", msg.param),
				))
			}
		}
	}()

	return c.Serve()
}
