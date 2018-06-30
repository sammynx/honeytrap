package ldap

import (
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

const (
	// LDAP App Codes
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

	// LDAP result codes
	ResSuccess         = 0
	ResOperationsError = 1
	ResProtocolError   = 2
	ResInvalidCred     = 49
)

type requestHandler interface {
	handle(*ber.Packet, eventLog) []*ber.Packet
}

type resultCodeHandler struct {
	replyTypeID int64 // the overall type of the response, e.g. 1 is BindResponse
	resultCode  int64 // the result code, i.e. 0 is success, 49 is invalid credentials, etc.
}

//Handle: the message envelope
func (h *resultCodeHandler) handle(p *ber.Packet, el eventLog) []*ber.Packet {

	id, err := messageID(p)
	if err != nil {
		el["ldap.message-id"] = -1
		log.Debugf("Unable to extract message ID: %s", err)
		return nil
	}

	el["ldap.message-id"] = id

	replypacket := ber.Encode(
		ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	replypacket.AppendChild(
		ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "MessageId"))
	bindResult := ber.Encode(
		ber.ClassApplication, ber.TypeConstructed, ber.Tag(h.replyTypeID), nil, "Response")
	bindResult.AppendChild(
		ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, h.resultCode, "Result Code"))
	// per the spec these are "matchedDN" and "diagnosticMessage", but we don't need them for this
	bindResult.AppendChild(
		ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Unused"))
	bindResult.AppendChild(
		ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Unused"))
	replypacket.AppendChild(bindResult)

	return []*ber.Packet{replypacket}
}

func isUnbindRequest(p *ber.Packet) bool {

	_, err := messageID(p)
	if err != nil {
		return false
	}

	err = checkPacket(p.Children[1], ber.ClassApplication, ber.TypePrimitive, 0x02)
	if err != nil {
		return false
	}

	return true
}

func messageID(p *ber.Packet) (int64, error) {

	// check overall packet header
	err := checkPacket(p, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence)
	if err != nil {
		return -1, err
	}

	// check type of message id
	err = checkPacket(p.Children[0], ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger)
	if err != nil {
		return -1, err
	}

	// return the message id
	return forceInt64(p.Children[0].Value), nil
}

//checkPacket: check a ber packet for correct class, type and tag
func checkPacket(p *ber.Packet, cl ber.Class, ty ber.Type, ta ber.Tag) error {
	if p.ClassType != cl {
		return fmt.Errorf("Check packet: Incorrect class, expected %v but got %v", cl, p.ClassType)
	}
	if p.TagType != ty {
		return fmt.Errorf("Check packet: Incorrect type, expected %v but got %v", cl, p.TagType)
	}
	if p.Tag != ta {
		return fmt.Errorf("Check packet: Incorrect tag, expected %v but got %v", cl, p.Tag)
	}

	return nil
}

// readVersion: Return the LDAP major version from the message
func readVersion(p *ber.Packet) int64 {

	if len(p.Children) > 0 && len(p.Children[1].Children) > 0 {
		err := checkPacket(p.Children[1].Children[0], ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger)
		if err != nil {
			log.Debugf("Error can not read the ldap version: %s", err)
			return -1
		}
		return forceInt64(p.Children[1].Children[0].Value)
	}

	log.Debug("Error can not read the ldap version")

	return -1
}

func forceInt64(v interface{}) int64 {
	switch v := v.(type) {
	case int64:
		return v
	case uint64:
		return int64(v)
	case int32:
		return int64(v)
	case uint32:
		return int64(v)
	case int:
		return int64(v)
	case byte:
		return int64(v)
	default:
		log.Panicf("forceInt64 doesn't understand values of type: %t", v)
	}
	// We shouldn't get here, but Go wants a return
	return 0
}
