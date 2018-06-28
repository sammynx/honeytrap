package ldap

import ber "github.com/go-asn1-ber/asn1-ber"

// LDAP App Codes
const (
	AppBindRequest           = 0
	AppBindResponse          = 1
	AppUnbindRequest         = 2
	AppSearchRequest         = 3
	AppSearchResultEntry     = 4
	AppSearchResultDone      = 5
	AppModifyRequest         = 6
	AppModifyResponse        = 7
	AppAddRequest            = 8
	AppAddResponse           = 9
	AppDelRequest            = 10
	AppDelResponse           = 11
	AppModifyDNRequest       = 12
	AppModifyDNResponse      = 13
	AppCompareRequest        = 14
	AppCompareResponse       = 15
	AppAbandonRequest        = 16
	AppSearchResultReference = 19
	AppExtendedRequest       = 23
	AppExtendedResponse      = 24
)

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
	case AppSearchResultReference:
		el["ldap.request-type"] = "search-result-reference"
	case AppExtendedRequest:
		el["ldap.request-type"] = "extended"
		reth.replyTypeID = AppExtendedResponse
	default:
		el["ldap.request-type"] = opcode
	}
	return reth.handle(p, el)
}
