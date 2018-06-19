package ldap

// Handle simple bind requests

import ber "github.com/asn1-ber"

// function that checks simple auth credentials (username/password style)
type BindFunc func(binddn string, bindpw []byte) bool

// responds to bind requests
type BindFuncHandler struct {
	BindFunc BindFunc
}

func (h *BindFuncHandler) Handle(p *ber.Packet, el eventLog) []*ber.Packet {
	reth := &ResultCodeHandler{ReplyTypeId: 1, ResultCode: 49}

	// check for bind request contents
	err := CheckPacket(p.Children[1], ber.ClassApplication, ber.TypeConstructed, 0x0)
	if err != nil {
		// Package is not meant for us
		return nil
	}

	// If we are here we have a bind request
	el["ldap.request"] = "BIND"

	// make sure we have at least our version number, bind dn and bind password
	if len(p.Children[1].Children) < 3 {
		el["ldap.malformed-payload"] = p.Data.Bytes()
		log.Debugf("At least 3 elements required in bind request, found %v", len(p.Children[1].Children))
		return nil
	}

	// the bind DN (the "username")
	err = CheckPacket(p.Children[1].Children[1], ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString)
	if err != nil {
		el["ldap.malformed-payload"] = p.Data.Bytes()
		log.Debugf("Error verifying packet: %v", err)
		return nil
	}

	myBindDn := string(p.Children[1].Children[1].ByteValue)

	err = CheckPacket(p.Children[1].Children[2], ber.ClassContext, ber.TypePrimitive, 0x0)
	if err != nil {
		el["ldap.malformed-payload"] = p.Data.Bytes()
		log.Debugf("Error verifying packet: %v", err)
		return nil
	}

	myBindPw := p.Children[1].Children[2].Data.Bytes()

	// call back to the auth handler
	if h.BindFunc(myBindDn, myBindPw) {
		// it worked, result code should be zero
		reth.ResultCode = 0
	}

	return reth.Handle(p, el)
}
