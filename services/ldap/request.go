package ldap

import "bufio"

type Request struct {
}

func ReadRequest(b *bufio.Reader) (*Request, error) {
	return &Request{}, nil
}
