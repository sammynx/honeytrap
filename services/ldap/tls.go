package ldap

import (
	"crypto/tls"
	"net"

	ber "github.com/asn1-ber"
)

type tlsFunc func(s *ldapService) (net.Conn, *tls.Config)

type tlsFuncHandler struct {
	tlsFunc tlsFunc
}

var tlsIdent = "1.3.6.1.4.1.1466.20037"

func (t *tlsFuncHandler) handle(p *ber.Packet, el eventLog) []*ber.Packet {
	reth := &resultCodeHandler{replyTypeID: AppExtendedResponse, resultCode: ResProtocolError}

	return reth.handle(p, el)
}

func isTLSRequest(p *ber.Packet) bool {
	if p == nil || len(p.Children) < 2 {
		return false
	}

	// check if package is for us
	err := checkPacket(p.Children[1], ber.ClassApplication, ber.TypeConstructed, AppExtendedRequest)
	if err != nil {
		return false
	}

	err = checkPacket(p.Children[1].Children[0], ber.ClassContext, ber.TypePrimitive, 0)
	if err != nil {
		return false
	}

	// not a tls request
	if tlsIdent != string(p.Children[1].Children[0].ByteValue) {
		return false
	}

	return true
}
