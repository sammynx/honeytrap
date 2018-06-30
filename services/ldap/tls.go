package ldap

import (
	ber "github.com/go-asn1-ber/asn1-ber"
)

type tlsFunc func() error

type tlsFuncHandler struct {
	tlsFunc tlsFunc
}

var tlsIdent = "1.3.6.1.4.1.1466.20037"

func (t *tlsFuncHandler) handle(p *ber.Packet, el eventLog) []*ber.Packet {
	reth := &resultCodeHandler{replyTypeID: AppExtendedResponse, resultCode: ResProtocolError}

	if p == nil || len(p.Children) < 2 {
		return nil
	}

	// check if package is for us
	err := checkPacket(p.Children[1], ber.ClassApplication, ber.TypeConstructed, AppExtendedRequest)
	if err != nil {
		return nil
	}

	err = checkPacket(p.Children[1].Children[0], ber.ClassContext, ber.TypePrimitive, 0)
	if err != nil {
		return nil
	}

	// not a tls request
	if tlsIdent != string(p.Children[1].Children[0].ByteValue) {
		return nil
	}

	// We have a tls request
	if err := t.tlsFunc(); err != nil {
		log.Debugf("LDAP: TLS Error: %s", err)
	}

	el["ldap.request-type"] = "tls"

	return reth.handle(p, el)
}
