// Package pop implements proof of possession for the UAI API: RFC 9421 HTTP
// message signatures, RFC 9530 content digests, and challenge-response with
// audience binding.
//
// The rule this package exists to enforce: `agent_id` in a JSON body proves
// nothing. Any process that can write the body can write the identifier. A
// state-changing call must carry a signature from a key the caller
// demonstrably controls (INV-002).
//
// # Domain separation in HTTP signatures
//
// Everywhere else in UAI a signature covers DOMAIN || 0x00 || payload. HTTP
// message signatures are the deliberate exception: RFC 9421 already carries the
// domain inside the signature base, as the `tag` parameter of
// @signature-params, which is itself a signed component. Prefixing the base
// with the UAI domain as well would add no security property and would break
// interoperability with standard RFC 9421 verifiers — the tag is checked
// explicitly on verification instead.
package pop

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

var (
	// ErrMissingComponent is returned when a covered component is absent.
	ErrMissingComponent = errors.New("pop: covered component missing from the message")
	// ErrUnsupportedComponent is returned for a derived component this package does not implement.
	ErrUnsupportedComponent = errors.New("pop: unsupported derived component")
	// ErrMalformedParams is returned for an unparsable Signature-Input value.
	ErrMalformedParams = errors.New("pop: malformed signature parameters")
)

// Params are the RFC 9421 signature parameters. Tag carries the UAI domain.
type Params struct {
	Components []string // covered component identifiers, in signing order
	Created    int64    // unix seconds
	Expires    int64    // unix seconds, 0 when absent
	KeyID      string   // DID URL of the verification method
	Alg        string   // "ed25519", "ecdsa-p256-sha256", "ecdsa-p384-sha384"
	Tag        string   // UAI domain separation string
	Nonce      string   // optional RFC 9421 nonce (UAI uses the UAI-Nonce field instead)
}

// DefaultComponents are the components UAI requires on a state-changing call.
//
// Content-Digest is covered so that the body cannot be swapped; UAI-Agent-Id
// and UAI-Nonce are covered so that neither the claimed identity nor the replay
// token can be altered without invalidating the signature.
var DefaultComponents = []string{
	"@method", "@target-uri", "content-digest", "uai-agent-id", "uai-nonce",
}

// Serialize renders the signature parameters as an RFC 8941 inner list with
// parameters, which is both the value of Signature-Input and the final line of
// the signature base.
func (p Params) Serialize() string {
	var b strings.Builder
	b.WriteByte('(')
	for i, c := range p.Components {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(strconv.Quote(strings.ToLower(c)))
	}
	b.WriteByte(')')
	if p.Created != 0 {
		b.WriteString(";created=" + strconv.FormatInt(p.Created, 10))
	}
	if p.Expires != 0 {
		b.WriteString(";expires=" + strconv.FormatInt(p.Expires, 10))
	}
	if p.KeyID != "" {
		b.WriteString(";keyid=" + strconv.Quote(p.KeyID))
	}
	if p.Alg != "" {
		b.WriteString(";alg=" + strconv.Quote(p.Alg))
	}
	if p.Nonce != "" {
		b.WriteString(";nonce=" + strconv.Quote(p.Nonce))
	}
	if p.Tag != "" {
		b.WriteString(";tag=" + strconv.Quote(p.Tag))
	}
	return b.String()
}

// Message is the subset of an HTTP request the signature covers. It is an
// interface so that both a client-side *http.Request and a server-side one can
// be signed and verified without copying.
type Message struct {
	Method string
	URL    *url.URL
	Header http.Header
}

// FromRequest builds a Message from an HTTP request.
//
// targetURI matters: a server-side request has a relative URL and the authority
// in the Host header, so the absolute target must be reconstructed. Getting
// this wrong makes signatures verify against the wrong resource, which is why
// the scheme is an explicit argument rather than a guess.
func FromRequest(r *http.Request, scheme string) Message {
	u := *r.URL
	if u.Host == "" {
		u.Host = r.Host
	}
	if u.Scheme == "" {
		u.Scheme = scheme
	}
	return Message{Method: r.Method, URL: &u, Header: r.Header}
}

// SignatureBase builds the RFC 9421 signature base: one line per covered
// component, then the @signature-params line with no trailing newline.
func SignatureBase(m Message, p Params) ([]byte, error) {
	if len(p.Components) == 0 {
		return nil, fmt.Errorf("%w: no covered components", ErrMalformedParams)
	}
	seen := map[string]bool{}
	var b strings.Builder
	for _, raw := range p.Components {
		name := strings.ToLower(raw)
		if seen[name] {
			return nil, fmt.Errorf("%w: component %q listed twice", ErrMalformedParams, name)
		}
		seen[name] = true

		value, err := componentValue(m, name)
		if err != nil {
			return nil, err
		}
		b.WriteString(strconv.Quote(name))
		b.WriteString(": ")
		b.WriteString(value)
		b.WriteByte('\n')
	}
	b.WriteString(strconv.Quote("@signature-params"))
	b.WriteString(": ")
	b.WriteString(p.Serialize())
	return []byte(b.String()), nil
}

func componentValue(m Message, name string) (string, error) {
	if strings.HasPrefix(name, "@") {
		switch name {
		case "@method":
			return strings.ToUpper(m.Method), nil
		case "@target-uri":
			if m.URL == nil {
				return "", fmt.Errorf("%w: @target-uri", ErrMissingComponent)
			}
			return m.URL.String(), nil
		case "@authority":
			if m.URL == nil {
				return "", fmt.Errorf("%w: @authority", ErrMissingComponent)
			}
			return strings.ToLower(m.URL.Host), nil
		case "@scheme":
			return strings.ToLower(m.URL.Scheme), nil
		case "@path":
			if m.URL.Path == "" {
				return "/", nil
			}
			return m.URL.Path, nil
		case "@query":
			return "?" + m.URL.RawQuery, nil
		default:
			return "", fmt.Errorf("%w: %s", ErrUnsupportedComponent, name)
		}
	}

	values := m.Header.Values(http.CanonicalHeaderKey(name))
	if len(values) == 0 {
		return "", fmt.Errorf("%w: %s", ErrMissingComponent, name)
	}
	// RFC 9421 section 2.1: trim each value, join repeated fields with ", ".
	trimmed := make([]string, 0, len(values))
	for _, v := range values {
		trimmed = append(trimmed, strings.TrimSpace(collapseObsFold(v)))
	}
	return strings.Join(trimmed, ", "), nil
}

// collapseObsFold replaces obsolete line folding with a single space, as
// required before a folded field value can be canonicalized.
func collapseObsFold(v string) string {
	if !strings.ContainsAny(v, "\r\n") {
		return v
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '\r', '\n':
			// skip, and swallow the following whitespace
			for i+1 < len(v) && (v[i+1] == ' ' || v[i+1] == '\t' || v[i+1] == '\r' || v[i+1] == '\n') {
				i++
			}
			b.WriteByte(' ')
		default:
			b.WriteByte(v[i])
		}
	}
	return b.String()
}

// ParseSignatureInput parses a Signature-Input header value into the label and
// its parameters. Only a single signature per message is supported, which is
// what the UAI API uses.
func ParseSignatureInput(value string) (label string, p Params, err error) {
	label, rest, ok := strings.Cut(strings.TrimSpace(value), "=")
	if !ok {
		return "", Params{}, fmt.Errorf("%w: expected <label>=(...)", ErrMalformedParams)
	}
	label = strings.TrimSpace(label)
	rest = strings.TrimSpace(rest)
	if !strings.HasPrefix(rest, "(") {
		return "", Params{}, fmt.Errorf("%w: expected an inner list", ErrMalformedParams)
	}
	close := strings.Index(rest, ")")
	if close < 0 {
		return "", Params{}, fmt.Errorf("%w: unterminated inner list", ErrMalformedParams)
	}

	inner := rest[1:close]
	for _, tok := range strings.Fields(inner) {
		unquoted, err := strconv.Unquote(tok)
		if err != nil {
			return "", Params{}, fmt.Errorf("%w: component %q", ErrMalformedParams, tok)
		}
		p.Components = append(p.Components, strings.ToLower(unquoted))
	}

	for _, seg := range splitParams(rest[close+1:]) {
		k, v, ok := strings.Cut(seg, "=")
		if !ok {
			continue
		}
		switch k {
		case "created":
			p.Created, _ = strconv.ParseInt(v, 10, 64)
		case "expires":
			p.Expires, _ = strconv.ParseInt(v, 10, 64)
		case "keyid":
			p.KeyID, _ = strconv.Unquote(v)
		case "alg":
			p.Alg, _ = strconv.Unquote(v)
		case "nonce":
			p.Nonce, _ = strconv.Unquote(v)
		case "tag":
			p.Tag, _ = strconv.Unquote(v)
		}
	}
	if len(p.Components) == 0 {
		return "", Params{}, fmt.Errorf("%w: no covered components", ErrMalformedParams)
	}
	return label, p, nil
}

// splitParams splits ";a=1;b=\"x;y\"" respecting quoted strings.
func splitParams(s string) []string {
	var out []string
	var cur strings.Builder
	inQuotes := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQuotes = !inQuotes
			cur.WriteByte(c)
		case c == ';' && !inQuotes:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
