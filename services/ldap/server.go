package ldap

import "crypto/tls"

//Server ldap server data
type Server struct {
	Handlers []requestHandler

	Credentials []string `toml:"credentials"`

	tlsConfig *tls.Config

	*DSE

	login string // username of logged in user
}

func (s Server) isLogin() bool {
	return s.login != ""
}

type DSE struct {
	NamingContexts       []string `toml:"naming-contexts"`
	SupportedLDAPVersion []string `toml:"supported-ldap-version"`
	SupportedExtension   []string `toml:"supported-extension"`
	VendorName           []string `toml:"vendor-name"`
	VendorVersion        []string `toml:"vendor-version"`
}

// Get return the rootDSE as search result
func (d *DSE) Get() *SearchResultEntry {
	return &SearchResultEntry{
		DN: "",
		Attrs: AttributeMap{
			"namingContexts":       d.NamingContexts,
			"supportedLDAPVersion": d.SupportedLDAPVersion,
			"supportedExtension":   d.SupportedExtension,
			"vendorName":           d.VendorName,
			"vendorVersion":        d.VendorVersion,
		},
	}
}
