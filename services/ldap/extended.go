/* * Honeytrap
* Copyright (C) 2016-2018 DutchSec (https://dutchsec.com/)
*
* This program is free software; you can redistribute it and/or modify it under
* the terms of the GNU Affero General Public License version 3 as published by the
* Free Software Foundation.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
* FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more
* details.
*
* You should have received a copy of the GNU Affero General Public License
* version 3 along with this program in the file "LICENSE".  If not, see
* <http://www.gnu.org/licenses/agpl-3.0.txt>.
*
* See https://honeytrap.io/ for more details. All requests should be sent to
* licensing@honeytrap.io
*
* The interactive user interfaces in modified source and object code versions
* of this program must display Appropriate Legal Notices, as required under
* Section 5 of the GNU Affero General Public License version 3.
*
* In accordance with Section 7(b) of the GNU Affero General Public License version 3,
* these Appropriate Legal Notices must retain the display of the "Powered by
* Honeytrap" logo and retain the original copyright notice. If the display of the
* logo is not reasonably feasible for technical reasons, the Appropriate Legal Notices
* must display the words "Powered by Honeytrap" and retain the original copyright notice.
 */
package ldap

import (
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

type extFunc func() error

type extFuncHandler struct {
	extFunc extFunc
}

var tlsOID = "1.3.6.1.4.1.1466.20037"

func (e *extFuncHandler) handle(p *ber.Packet, el eventLog) []*ber.Packet {
	reth := &resultCodeHandler{replyTypeID: AppExtendedResponse, resultCode: ResProtocolError}

	log.Debug("Start extFuncHandler...")

	// too small to be an extended request
	if p == nil || len(p.Children) < 2 {
		return nil
	}

	// check if package is an extended request
	err := checkPacket(p.Children[1], ber.ClassApplication, ber.TypeConstructed, AppExtendedRequest)
	if err != nil {
		return nil
	}

	el["ldap.request-type"] = "extended"

	// is there an OID and optional value
	if len(p.Children[1].Children) > 0 {
		ber.PrintPacket(p)

		err = checkPacket(p.Children[1].Children[0], ber.ClassContext, ber.TypePrimitive, 0)
		if err != nil {
			// this is not an OID
			return nil
		}

		oid := p.Children[1].Children[0].Data.String()

		el["ldap.extended-oid"] = oid

		fmt.Printf("ldap.extended-oid %s\n", el["ldap.extended-oid"].(string))

		// catch value if we have one
		if len(p.Children[1].Children) > 1 {
			el["ldap.extended-oid-value"] = p.Children[1].Children[1].Bytes()
		}

	}

	if tlsOID == el["ldap.extended-oid"].(string) {
		el["ldap.request-type"] = "extended.tls"

		log.Debug("start extFunc...")

		err := e.extFunc()
		if err == nil {
			reth.resultCode = ResSuccess
			reth.matchedDN = el["ldap.extended-oid"].(string)
		}
		log.Debugf("extFunc err: %s", err)
	}

	return reth.handle(p, el)
}
