package ldap

// Handle simple bind requests

import (
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
)

//bindFunc checks simple auth credentials (username/password style)
type bindFunc func(binddn string, bindpw []byte) bool

//bindFuncHandler: responds to bind requests
type bindFuncHandler struct {
	bindFunc bindFunc
}

func (h *bindFuncHandler) handle(p *ber.Packet, el eventLog) []*ber.Packet {
	reth := &resultCodeHandler{replyTypeID: 1, resultCode: 49}

	// check for bind request contents
	if p == nil || len(p.Children) < 2 {
		// Package is not meant for us
		return nil
	}
	err := checkPacket(p.Children[1], ber.ClassApplication, ber.TypeConstructed, 0x0)
	if err != nil {
		// Package is not meant for us
		return nil
	}

	// If we are here we have a bind request
	el["ldap.request-type"] = "bind"

	version := readVersion(p)
	el["ldap.version"] = version

	if version < 3 {
		reth.resultCode = 2 // protocolError
		return reth.handle(p, el)
	}

	// make sure we have at least our version number, bind dn and bind password
	if len(p.Children[1].Children) < 3 {
		el["ldap.malformed-payload"] = p.Data.Bytes()
		log.Debugf("At least 3 elements required in bind request, found %v", len(p.Children[1].Children))
		return nil
	}

	// the bind DN (the "username")
	err = checkPacket(p.Children[1].Children[1], ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString)
	if err != nil {
		el["ldap.malformed-payload"] = p.Data.Bytes()
		log.Debugf("Error verifying packet: %v", err)
		return nil
	}

	bindDn := strings.TrimPrefix(string(p.Children[1].Children[1].ByteValue), "cn=")
	log.Debugf("ldap name: %s", bindDn)
	if index := strings.Index(bindDn, ","); index > -1 {
		bindDn = bindDn[:index]
	}

	log.Debugf("ldap name: %s", bindDn)
	el["ldap.username"] = bindDn

	err = checkPacket(p.Children[1].Children[2], ber.ClassContext, ber.TypePrimitive, 0x0)
	if err != nil {
		el["ldap.malformed-payload"] = p.Data.Bytes()
		log.Debugf("Error verifying packet: %v", err)
		return nil
	}

	bindPw := p.Children[1].Children[2].Data.Bytes()

	el["ldap.password"] = string(bindPw)

	// call back to the auth handler
	if h.bindFunc(bindDn, bindPw) {
		// it worked, result code should be zero for success
		reth.resultCode = 0
	}

	return reth.handle(p, el)
}
