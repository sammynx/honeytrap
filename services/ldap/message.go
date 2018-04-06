package ldap

import ber "github.com/honeytrap/honeytrap/services/asn1-ber"

// LDAP Application Codes
const (
	ApplicationBindRequest           = 0
	ApplicationBindResponse          = 1
	ApplicationUnbindRequest         = 2
	ApplicationSearchRequest         = 3
	ApplicationSearchResultEntry     = 4
	ApplicationSearchResultDone      = 5
	ApplicationModifyRequest         = 6
	ApplicationModifyResponse        = 7
	ApplicationAddRequest            = 8
	ApplicationAddResponse           = 9
	ApplicationDelRequest            = 10
	ApplicationDelResponse           = 11
	ApplicationModifyDNRequest       = 12
	ApplicationModifyDNResponse      = 13
	ApplicationCompareRequest        = 14
	ApplicationCompareResponse       = 15
	ApplicationAbandonRequest        = 16
	ApplicationSearchResultReference = 19
	ApplicationExtendedRequest       = 23
	ApplicationExtendedResponse      = 24
)

var appCodes = map[int]string{
	ApplicationBindRequest:           "BindRequest",
	ApplicationBindResponse:          "BindResponse",
	ApplicationUnbindRequest:         "UnbindRequest",
	ApplicationSearchRequest:         "SearchRequest",
	ApplicationSearchResultEntry:     "SearchResultEntry",
	ApplicationSearchResultDone:      "SearchResultDone",
	ApplicationModifyRequest:         "ModifyRequest",
	ApplicationModifyResponse:        "ModifyResponse",
	ApplicationAddRequest:            "AddRequest",
	ApplicationAddResponse:           "AddResponse",
	ApplicationDelRequest:            "DelRequest",
	ApplicationDelResponse:           "DelResponse",
	ApplicationModifyDNRequest:       "ModifyDNRequest",
	ApplicationModifyDNResponse:      "ModifyDNResponse",
	ApplicationCompareRequest:        "CompareRequest",
	ApplicationCompareResponse:       "CompareResponse",
	ApplicationAbandonRequest:        "AbandonRequest",
	ApplicationSearchResultReference: "SearchResultReference",
	ApplicationExtendedRequest:       "ExtendedRequest",
	ApplicationExtendedResponse:      "ExtendedResponse",
}

// LDAP message
type Message struct {
	id         int
	protocolOp int
	control    []Control
}

type Control struct {
	controlType int
	criticality bool
	value       string
}

func NewMessage(p *ber.Packet) (*Message, error) {

	m := &Message{
		id:         int(p.Children[0].Value.(int64)),
		protocolOp: int(p.Children[1].Tag),
	}

	//ASN.1 BER decode req

	return m, nil
}

// Return an ASN.1 BER/DER encoded LDAP response packet
func (m *Message) Response() (*ber.Packet, error) {
	var (
		err error
		pc  *ber.Packet
	)

	p := m.envelope()

	switch m.protocolOp {
	case ApplicationBindRequest:
		pc, err = simpleBind()
		p.AppendChild(pc)
	case ApplicationUnbindRequest:
	case ApplicationAbandonRequest:
	case ApplicationAddRequest:
	case ApplicationSearchRequest:
	case ApplicationModifyRequest:
	case ApplicationDelRequest:
	case ApplicationModifyDNRequest:
	case ApplicationCompareRequest:
	case ApplicationExtendedRequest:
	}

	if err != nil {
		return nil, err
	}

	return p, nil
}

//Create a Response from ldap message
func (m *Message) envelope() *ber.Packet {

	p := ber.NewSequence("LDAP Response")
	p.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		m.id,
		"MessageID",
	))

	return p
}

func simpleBind() (*ber.Packet, error) {

	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindResponse, nil, "Bind Response")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "Succes"))
	p.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	p.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))

	return p, nil
}
