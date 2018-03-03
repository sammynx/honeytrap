package ldap

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

func NewMessage(req []byte) (*Message, error) {

	msg := &Message{}

	//ASN.1 BER decode req

	return msg, nil
}

func (m *Message) Response() ([]byte, error) {

	if err := m.handle(); err != nil {
		return nil, err
	}

	//ASN.1 BER/DER encode m

	asn1_b, err := m.encode()

	return asn1_b, err
}

//Create a Response from ldap message
func (m *Message) handle() error {

	//Set m to be the response for this message
	err := nil

	return err
}

func (m *Message) encode() ([]byte, error) {

}
