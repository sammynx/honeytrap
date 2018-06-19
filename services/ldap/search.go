package ldap

import (
	"fmt"

	ber "github.com/asn1-ber"
)

// a simplified ldap search request
type SearchRequest struct {
	Packet       *ber.Packet
	BaseDN       string // DN under which to start searching
	Scope        int64  // baseObject(0), singleLevel(1), wholeSubtree(2)
	DerefAliases int64  // neverDerefAliases(0),derefInSearching(1),derefFindingBaseObj(2),derefAlways(3)
	SizeLimit    int64  // max number of results to return
	TimeLimit    int64  // max time in seconds to spend processing
	TypesOnly    bool   // if true client is expecting only type info
	FilterAttr   string // filter attribute name (assumed to be an equality match with just this one attribute)
	FilterValue  string // filter attribute value
}

var (
	ErrNotASearchRequest       = fmt.Errorf("not a search request!")
	ErrSearchRequestTooComplex = fmt.Errorf("search too complex to be parsed!")
)

func ParseSearchRequest(p *ber.Packet) (*SearchRequest, error) {

	ret := &SearchRequest{}

	if len(p.Children) < 2 {
		return nil, ErrNotASearchRequest
	}

	err := CheckPacket(p.Children[1], ber.ClassApplication, ber.TypeConstructed, 0x3)
	if err != nil {
		return nil, ErrNotASearchRequest
	}

	rps := p.Children[1].Children

	ret.BaseDN = string(rps[0].ByteValue)
	ret.Scope = ForceInt64(rps[1].Value)
	ret.DerefAliases = ForceInt64(rps[2].Value)
	ret.SizeLimit = ForceInt64(rps[3].Value)
	ret.TimeLimit = ForceInt64(rps[4].Value)
	ret.TypesOnly = rps[5].Value.(bool)

	// Check to see if it looks like a simple search criteria
	err = CheckPacket(rps[6], ber.ClassContext, ber.TypeConstructed, 0x3)
	if err == nil {
		// It is simple, return the attribute and value
		ret.FilterAttr = string(rps[6].Children[0].ByteValue)
		ret.FilterValue = string(rps[6].Children[1].ByteValue)
	} else {
		// This is likely some sort of complex search criteria.
		// Try to generate a searchFingerPrint based on the values
		// You will have to understand this fingerprint in your code
		var getContextValue func(p *ber.Packet) string
		getContextValue = func(p *ber.Packet) string {
			ret := ""
			if p.Value != nil {
				ret = fmt.Sprint(p.Value)
			}
			for _, child := range p.Children {
				childVal := getContextValue(child)
				if childVal != "" {
					if ret != "" {
						ret += ","
					}
					ret += childVal
				}
			}
			return ret
		}

		ret.FilterAttr = "searchFingerprint"
		ret.FilterValue = getContextValue(rps[6])
		for index := 7; index < len(rps); index++ {
			value := getContextValue(rps[index])
			if value != "" {
				if ret.FilterValue != "" {
					ret.FilterValue += ","
				}
				ret.FilterValue += value
			}
		}

	}

	return ret, nil

}

// a simplified ldap search response
type SearchResultEntry struct {
	DN    string                 // DN of this search result
	Attrs map[string]interface{} // map of attributes
}

func (e *SearchResultEntry) MakePacket(msgid int64) *ber.Packet {

	messageId := msgid

	replypacket := ber.Encode(
		ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	replypacket.AppendChild(
		ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageId, "MessageId"))
	searchResult := ber.Encode(
		ber.ClassApplication, ber.TypeConstructed, ber.Tag(4), nil, "Response")
	searchResult.AppendChild(
		ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.DN, "DN"))
	attrs := ber.Encode(
		ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attrs")

	for k, v := range e.Attrs {

		attr := ber.Encode(
			ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attr")
		attr.AppendChild(
			ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, k, "Key"))
		attrvals := ber.Encode(
			ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "Values")

		switch v := v.(type) {
		case string:
			attrvals.AppendChild(
				ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "String Value"))
		case []string:
			for _, v1 := range v {
				attrvals.AppendChild(
					ber.NewString(
						ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v1, "String Value"))
			}
		default:
			log.Debugf("skipping value for key '%s', I can't process type '%t'", k, v)
			continue
		}

		attr.AppendChild(attrvals)
		attrs.AppendChild(attr)

	}
	searchResult.AppendChild(attrs)

	replypacket.AppendChild(searchResult)

	return replypacket

}

func MakeSearchResultDonePacket(msgid int64) *ber.Packet {

	messageID := msgid

	replypacket := ber.Encode(
		ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	replypacket.AppendChild(
		ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageId"))
	searchResult := ber.Encode(
		ber.ClassApplication, ber.TypeConstructed, ber.Tag(5), nil, "Response")
	searchResult.AppendChild(
		ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "Result Code"))
	// per the spec these are "matchedDN" and "diagnosticMessage", but we don't need them for this
	searchResult.AppendChild(
		ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Unused"))
	searchResult.AppendChild(
		ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Unused"))
	replypacket.AppendChild(searchResult)

	return replypacket

}

func MakeSearchResultNoSuchObjectPacket(msgid int64) *ber.Packet {

	messageID := msgid

	replypacket := ber.Encode(
		ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	replypacket.AppendChild(
		ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageId"))
	searchResult := ber.Encode(
		ber.ClassApplication, ber.TypeConstructed, ber.Tag(5), nil, "Response")
	// 32 is "noSuchObject"
	searchResult.AppendChild(
		ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 32, "Result Code"))
	// per the spec these are "matchedDN" and "diagnosticMessage", but we don't need them for this
	searchResult.AppendChild(
		ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Unused"))
	searchResult.AppendChild(
		ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Unused"))
	replypacket.AppendChild(searchResult)

	return replypacket

}

// a callback function to produce search results; should return nil to mean
// we chose not to attempt to search (i.e. this request is not for us);
// or return empty slice to mean 0 results (or slice with data for results)
type SearchFunc func(*SearchRequest) []*SearchResultEntry

type SearchFuncHandler struct {
	SearchFunc SearchFunc
}

func (h *SearchFuncHandler) Handle(p *ber.Packet, el eventLog) []*ber.Packet {

	req, err := ParseSearchRequest(p)
	if err == ErrNotASearchRequest {
		return nil
	} else if err == ErrSearchRequestTooComplex {
		log.Debugf("Search request too complex, skipping")
		return nil
	} else if err != nil {
		log.Debugf("Error while trying to parse search request: %v", err)
		return nil
	}

	res := h.SearchFunc(req)

	// the function is telling us it is opting not to process this search request
	if res == nil {
		return nil
	}

	msgid, err := messageID(p)
	if err != nil {
		log.Debugf("Failed to extract message id")
		return nil
	}

	// no results
	if len(res) < 1 {
		return []*ber.Packet{MakeSearchResultNoSuchObjectPacket(msgid)}
	}

	// format each result
	ret := make([]*ber.Packet, 0)
	for _, resitem := range res {
		resultPacket := resitem.MakePacket(msgid)
		// fmt.Printf("--------------------\n")
		// ber.PrintPacket(resultPacket)
		ret = append(ret, resultPacket)
	}

	// end with a done packet
	ret = append(ret, MakeSearchResultDonePacket(msgid))

	return ret

}
