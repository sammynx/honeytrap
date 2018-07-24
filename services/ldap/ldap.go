/*
* Honeytrap
* Copyright (C) 2016-2018 DutchSec (https://dutchsec.com/)
*
* This program is free software; you can redistribute it and/or modify it under
* the terms of the GNU Affero General Public License version 3 as published by the
* Free Software Foundation.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
* FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more
* details.
*
* You should have received a copy of the GNU Affero General Public License
* version 3 along with this program in the file "LICENSE".  If not, see
* <http://www.gnu.org/licenses/agpl-3.0.txt>.
*
* See https://honeytrap.io/ for more details. All requests should be sent to
* licensing@honeytrap.io
*
* The interactive user interfaces in modified source and object code versions
* of this program must display Appropriate Legal Notices, as required under
* Section 5 of the GNU Affero General Public License version 3.
*
* In accordance with Section 7(b) of the GNU Affero General Public License version 3,
* these Appropriate Legal Notices must retain the display of the "Powered by
* Honeytrap" logo and retain the original copyright notice. If the display of the
* logo is not reasonably feasible for technical reasons, the Appropriate Legal Notices
* must display the words "Powered by Honeytrap" and retain the original copyright notice.
 */
package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/honeytrap/honeytrap/event"
	"github.com/honeytrap/honeytrap/pushers"
	"github.com/honeytrap/honeytrap/services"
	logging "github.com/op/go-logging"
)

/*

[service.ldap]
type="ldap"
credentials=[ "user:password", "admin:admin" ]

[[port]]
port="tcp/389"
services=[ "ldap" ]

[[port]]
port="udp/389"
services=[ "ldap" ]

#LDAPS
[[port]]
port="tcp/636"
services=["ldap"]

*/

var (
	_   = services.Register("ldap", LDAP)
	log = logging.MustGetLogger("services/ldap")
)

// LDAP service setup
func LDAP(options ...services.ServicerFunc) services.Servicer {

	store, err := getStorage()
	if err != nil {
		log.Errorf("LDAP: Could not initialize storage. %s", err.Error())
	}

	cert, err := store.Certificate()
	if err != nil {
		log.Errorf("TLS: %s", err.Error())
	}

	s := &ldapService{
		Server: Server{
			Handlers: make([]requestHandler, 0, 4),

			Credentials: []string{"root:root"},

			tlsConfig: &tls.Config{
				Certificates:       []tls.Certificate{*cert},
				InsecureSkipVerify: true,
			},
		},
	}

	// Set request handlers
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

	*Conn

	wantTLS bool

	c pushers.Channel
}

//Server ldap server data
type Server struct {
	Handlers []requestHandler

	Credentials []string `toml:"credentials"`

	tlsConfig *tls.Config

	login string // username of logged in user
}

type eventLog map[string]interface{}

func (s *ldapService) setHandlers() {

	s.Handlers = append(s.Handlers,
		&extFuncHandler{
			tlsFunc: func() error {
				if s.tlsConfig != nil {
					s.wantTLS = true
					return nil
				}
				return errors.New("TLS not available")
			},
		})

	s.Handlers = append(s.Handlers,
		&bindFuncHandler{
			bindFunc: func(binddn string, bindpw []byte) bool {

				var cred strings.Builder // build "name:password" string
				_, err := cred.WriteString(binddn)
				_, err = cred.WriteRune(':') // separator
				_, err = cred.Write(bindpw)
				if err != nil {
					log.Debug("ldap.bind: couldn't construct bind name")
					return false
				}

				// anonymous bind is ok
				if cred.Len() == 1 { // empty credentials (":")
					s.login = ""
					return true
				}

				for _, u := range s.Credentials {
					if u == cred.String() {
						s.login = binddn
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

				// if not authenticated send only rootDSE else nothing
				if s.login == "" {
					if req.FilterAttr == "objectclass" && req.FilterValue == "" {
						ret = append(ret, &SearchResultEntry{
							DN: "",
							Attrs: map[string]interface{}{
								"namingContexts":       "",
								"supportedLDAPVersion": []string{"2", "3"},
								"supportedExtension":   "1.3.6.1.4.1.1466.20037",
								"vendorName":           "Jerry inc.",
								"vendorVersion":        "Jerry's directory server v2.0.0",
							},
						})
						return ret
					}
					return nil
				}

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
					return ret
				}
				return nil
			},
		})

	// CatchAll should be the last handler
	s.Handlers = append(s.Handlers,
		&CatchAll{
			isLogin: func() bool {
				return s.isLogin()
			},
		},
	)
}

func (s *ldapService) isLogin() bool {
	return s.login != ""
}

func (s *ldapService) SetChannel(c pushers.Channel) {

	s.c = c
}

func (s *ldapService) Handle(ctx context.Context, conn net.Conn) error {
	s.wantTLS = false

	s.login = "" // set the anonymous authstate

	s.Conn = NewConn(conn)

	for {

		p, err := ber.ReadPacket(s.ConnReader)
		if err != nil {
			return err
		}

		fmt.Println("-- REQUEST --")
		ber.PrintPacket(p)

		// check if packet is readable
		id, err := messageID(p)
		if err != nil {
			return err
		}

		// Storage for events
		elog := make(eventLog)

		elog["ldap.message-id"] = id

		// check if this is an unbind, if so we can close immediately

		if isUnbindRequest(p) {
			s.c.Send(event.New(
				services.EventOptions,
				event.Category("ldap"),
				event.SourceAddr(conn.RemoteAddr()),
				event.DestinationAddr(conn.LocalAddr()),
				event.Custom("ldap.message-id", id),
				event.Custom("ldap.request-type", "unbind"),
			))

			// We don't have to return anything, so we just close the connection
			return nil
		}

		// Handle request and create a response packet(ASN.1 BER)
		for _, h := range s.Handlers {
			plist := h.handle(p, elog)

			if len(plist) > 0 {
				fmt.Println("-- RESPONSE --")

				for _, part := range plist {
					ber.PrintPacket(part)

					if _, err := s.con.Write(part.Bytes()); err != nil {
						return err
					}
				}
				// request is handled
				break
			}
		}

		if s.wantTLS {
			s.wantTLS = false
			if err := s.StartTLS(s.tlsConfig); err != nil {
				return err
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
