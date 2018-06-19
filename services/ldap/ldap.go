package ldap

import (
	"bufio"
	"context"
	"fmt"
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
		Server: Server{
			Handlers: make([]RequestHandler, 2),

			Users: []User{User{"root", "root"}},
		},
	}

	// Set requestHandlers
	s.setHandlers()

	for _, o := range options {
		if err := o(s); err != nil {
			log.Warning(err.Error())
		}
	}

	return s
}

type ldapService struct {
	Server

	c pushers.Channel
}

type Server struct {
	Handlers []RequestHandler

	Users []User
}

type User struct {
	name, password string
}

type eventLog map[string]interface{}

func (s *ldapService) setHandlers() {

	s.Handlers = append(
		s.Handlers,
		&BindFuncHandler{
			BindFunc: func(binddn string, bindpw []byte) bool {
				for _, u := range s.Users {
					// binddn starts with cn=
					if u.name == binddn[3:] && u.password == string(bindpw) {
						return true
					}
				}
				return false
			},
		},
		&SearchFuncHandler{
			SearchFunc: func(req *SearchRequest) []*SearchResultEntry {

				ret := make([]*SearchResultEntry, 0, 1)

				// produce a single search result that matches whatever
				// they are searching for
				if req.FilterAttr == "uid" {
					ret = append(ret, &SearchResultEntry{
						DN: "cn=" + req.FilterValue + "," + req.BaseDN,
						Attrs: map[string]interface{}{
							"sn":            req.FilterValue,
							"cn":            req.FilterValue,
							"uid":           req.FilterValue,
							"homeDirectory": "/home/" + req.FilterValue,
							"objectClass": []string{
								"top",
								"posixAccount",
								"inetOrgPerson",
							},
						},
					})
				}
				return ret
			},
		},
	)
}

func (s *ldapService) SetChannel(c pushers.Channel) {

	s.c = c
}

func (s *ldapService) Handle(ctx context.Context, conn net.Conn) error {

	elog := make(eventLog, 4)

	br := bufio.NewReader(conn)

	for {

		p, err := ber.ReadPacket(br)
		if err != nil {
			return err
		}

		version := checkVersion(p)
		elog["ldap.version"] = version

		if version != 2 {
			return fmt.Errorf("Wrong LDAP version: v%d. Required v2.", version)
		}

		if IsUnbindRequest(p) {
			// Close the connection if unbind is requested and cleanup pending operatons if necessary
			return nil
		}

		// Handle request and create a response packet(ASN.1 BER)
		for _, h := range s.Handlers {
			plist := h.Handle(p, elog)

			if len(plist) > 0 {
				for _, part := range plist {
					if _, err := conn.Write(part.Bytes()); err != nil {
						return err
					}
				}
				// Handled the request, break out of the handling loop
				break
			}
		}

		// Send Message Data
		s.c.Send(event.New(
			services.EventOptions,
			event.Category("ldap"),
			event.SourceAddr(conn.RemoteAddr()),
			event.DestinationAddr(conn.LocalAddr()),
			event.CopyFrom(elog),
		))

	}

	return nil
}
