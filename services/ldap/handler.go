package ldap

import (
	"fmt"

	ber "github.com/asn1-ber"
)

type RequestHandler interface {
	Handle(*ber.Packet, eventLog) []*ber.Packet
}

type ResultCodeHandler struct {
	ReplyTypeId int64 // the overall type of the response, e.g. 1 is BindResponse
	ResultCode  int64 // the result code, i.e. 0 is success, 49 is invalid credentials, etc.
}

// Message envelope
func (h *ResultCodeHandler) Handle(p *ber.Packet, el eventLog) []*ber.Packet {

	id, err := messageID(p)
	if err != nil {
		el["ldap.message-id"] = 0
		log.Debugf("Unable to extract message ID: %s", err)
		return nil
	}

	el["ldap.message-id"] = id

	replypacket := ber.Encode(
		ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	replypacket.AppendChild(
		ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "MessageId"))
	bindResult := ber.Encode(
		ber.ClassApplication, ber.TypeConstructed, ber.Tag(h.ReplyTypeId), nil, "Response")
	bindResult.AppendChild(
		ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, h.ResultCode, "Result Code"))
	// per the spec these are "matchedDN" and "diagnosticMessage", but we don't need them for this
	bindResult.AppendChild(
		ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Unused"))
	bindResult.AppendChild(
		ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Unused"))
	replypacket.AppendChild(bindResult)

	return []*ber.Packet{replypacket}
}

func IsUnbindRequest(p *ber.Packet) bool {

	_, err := messageID(p)
	if err != nil {
		return false
	}

	err = CheckPacket(p.Children[1], ber.ClassApplication, ber.TypePrimitive, 0x2)
	if err != nil {
		return false
	}

	return true
}

// messageID: Extract the ID from an ldap message packet
func messageID(p *ber.Packet) (int64, error) {

	// check overall packet header
	err := CheckPacket(p, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence)
	if err != nil {
		return -1, err
	}

	// check type of message id
	err = CheckPacket(p.Children[0], ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger)
	if err != nil {
		return -1, err
	}

	// return the message id
	return ForceInt64(p.Children[0].Value), nil
}

// CheckPacket: check a ber packet for correct class, type and tag
func CheckPacket(p *ber.Packet, cl ber.Class, ty ber.Type, ta ber.Tag) error {
	if p.ClassType != cl {
		return fmt.Errorf("Incorrect class, expected %v but got %v", cl, p.ClassType)
	}
	if p.TagType != ty {
		return fmt.Errorf("Incorrect type, expected %v but got %v", cl, p.TagType)
	}
	if p.Tag != ta {
		return fmt.Errorf("Incorrect tag, expected %v but got %v", cl, p.Tag)
	}

	return nil
}

// checkVersion: Return the LDAP major version from the message
func checkVersion(p *ber.Packet) int64 {

	err := CheckPacket(p.Children[1].Children[0], ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger)
	if err != nil {
		log.Debugf("Error can not read the ldap version: %s", err)
		return 0
	}

	return ForceInt64(p.Children[1].Children[0].Value)
}

func ForceInt64(v interface{}) int64 {
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
		log.Panicf("ForceInt64 doesn't understand values of type: %t", v)
	}
	// We shouldn't get here, but Go wants a return
	return 0
}
