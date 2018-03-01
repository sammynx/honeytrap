package ldap

import "io"

type Response struct {
}

func (r *Response) Write(w io.Writer) error {
	return nil
}
