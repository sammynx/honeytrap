package ldap

import (
	"bytes"
	"reflect"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

var (
	// Bind request: cn=root,dc=example,dc=com password: root
	testRequestPacket = []byte{
		0x30, 0x29, 0x02, 0x01, 0x01, 0x60, 0x24, 0x02,
		0x01, 0x03, 0x04, 0x19, 0x63, 0x6e, 0x3d, 0x72,
		0x6f, 0x6f, 0x74, 0x2c, 0x64, 0x63, 0x3d, 0x65,
		0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2c, 0x64,
		0x63, 0x3d, 0x63, 0x6f, 0x6d, 0x80, 0x04, 0x72,
		0x6f, 0x6f, 0x74,
	}
	//succes message
	testResponsePacket = []byte{
		0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a,
		0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
	}
)

func TestHandle(t *testing.T) {
	cases := []struct {
		arg, want []byte
	}{
		//{testRequestPacket, testResponsePacket},
	}

	h := &bindFuncHandler{
		bindFunc: func(name string, pw []byte) bool {
			// Just check the name
			if name == "root" {
				return true
			}
			return false
		},
	}

	for _, c := range cases {
		p := ber.DecodePacket(c.arg)
		el := eventLog{}
		got := h.handle(p, el)
		var gotb bytes.Buffer

		for _, pack := range got {
			gotb.Write(pack.Bytes())
		}

		if !reflect.DeepEqual(gotb.Bytes(), c.want) {
			t.Errorf("Bind: want %v got %v arg %v", c.want, gotb, p.Bytes())
		}

		if rtype, ok := el["ldap.request-type"]; !ok || rtype != "bind" {
			t.Errorf("Bind: Wrong request type, want bind, got %s", rtype)
		}
	}
}

func TestHandleBad(t *testing.T) {
	cases := [][]byte{
		{},
		{0, 0, 0, 0, 0},
	}

	h := &bindFuncHandler{
		bindFunc: func(name string, pw []byte) bool {
			// Just check the name, so pw can be nil
			if name == "root" {
				return true
			}
			return false
		},
	}

	for _, c := range cases {
		el := make(eventLog)
		p := ber.DecodePacket(c)

		got := h.handle(p, el) // should return nil on bad input

		if got != nil {
			t.Errorf("Bind: No nil package on bad input. %v", p.Bytes())
		}

		// TODO: Check resultcode on bad/good creds
	}
}
