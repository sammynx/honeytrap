package ldap

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
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
			Handlers: make([]requestHandler, 0, 4),

			Users: []string{"root:root"},
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

//Server ldap server data
type Server struct {
	Handlers []requestHandler

	Users []string

	conn    net.Conn
	tlsConf *tls.Config
}

type eventLog map[string]interface{}

func (s *ldapService) setHandlers() {

	s.Handlers = append(s.Handlers,
		&tlsFuncHandler{
			tlsFunc: func() (net.Conn, *tls.Config) {
				return s.conn, s.tlsConf
			},
		})

	s.Handlers = append(s.Handlers,
		&bindFuncHandler{
			bindFunc: func(binddn string, bindpw []byte) bool {

				var cred strings.Builder           // build "name:password" string
				_, err := cred.WriteString(binddn) // binddn starts with cn=
				_, err = cred.WriteRune(':')       // separator
				_, err = cred.Write(bindpw)
				if err != nil {
					log.Debug("ldap.bind: couldn't construct bind name")
					return false
				}

				for _, u := range s.Users {
					if u == cred.String() {
						return true
					}
				}
				return false
			},
		})

	s.Handlers = append(s.Handlers,
		&searchFuncHandler{
			searchFunc: func(req *SearchRequest) []*SearchResultEntry {

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

	// CatchAll should be the last handler
	s.Handlers = append(s.Handlers, &CatchAll{})
}

func (s *ldapService) SetChannel(c pushers.Channel) {

	s.c = c
}

func (s *ldapService) Handle(ctx context.Context, conn net.Conn) error {
	s.conn = conn

	br := bufio.NewReader(conn)

	for {

		p, err := ber.ReadPacket(br)
		if err != nil {
			return err
		}

		ber.PrintPacket(p)

		// Storage for events
		elog := make(eventLog)

		if isUnbindRequest(p) {
			// Close the connection if unbind is requested and cleanup pending operatons if necessary
			elog["ldap.request-type"] = "unbind"
			return nil
		}

		// Handle request and create a response packet(ASN.1 BER)
		for _, h := range s.Handlers {
			plist := h.handle(p, elog)

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
}
