package ldap

import ber "github.com/go-asn1-ber/asn1-ber"

//CatchAll handles the not implemented LDAP requests
type CatchAll struct{}

func (c *CatchAll) handle(p *ber.Packet, el eventLog) []*ber.Packet {
	el["ldap.message"] = p.Bytes()

	// Check to see if packet is readable
	id, err := messageID(p)
	_ = id
	if err != nil {
		log.Debugf("LDAP: Can't read message id: %s", err)
		return nil
	}

	opcode := int(p.Children[1].Tag)

	// This initializes with 0 as resultcode (success)
	reth := &resultCodeHandler{}

	switch opcode {
	case AppModifyRequest:
		el["ldap.request-type"] = "modify"
		reth.replyTypeID = AppModifyResponse
	case AppAddRequest:
		el["ldap.request-type"] = "add"
		reth.replyTypeID = AppAddResponse
	case AppDelRequest:
		el["ldap.request-type"] = "delete"
		reth.replyTypeID = AppDelResponse
	case AppModifyDNRequest:
		el["ldap.request-type"] = "modify-dn"
		reth.replyTypeID = AppModifyDNResponse
	case AppCompareRequest:
		el["ldap.request-type"] = "compare"
		reth.replyTypeID = AppCompareResponse
	case AppAbandonRequest:
		el["ldap.request-type"] = "abandon"
		return nil // This needs no answer
	case AppExtendedRequest:
		el["ldap.request-type"] = "extended"
		reth.replyTypeID = AppExtendedResponse
	default:
		el["ldap.request-type"] = opcode
		reth.replyTypeID = 1 // protocolError
	}
	return reth.handle(p, el)
}
