package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/net/idna"
)

// canonicalIP normalizes an IP address string: IPv4 without leading zeros,
// IPv6 lowercased and compressed to its canonical form. An unparseable value
// falls back to a trimmed lowercase string so identity is still deterministic.
func canonicalIP(v string) string {
	s := strings.TrimSpace(v)
	ip := net.ParseIP(s)
	if ip == nil {
		return strings.ToLower(s)
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String() // net.IP.String already yields lowercase compressed IPv6
}

// canonicalDomain normalizes a domain name: lowercased, trailing dots stripped,
// IDN punycoded (ASCII/A-label). Punycoding failures fall back to the
// lowercased form.
func canonicalDomain(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	s = strings.TrimRight(s, ".")
	if s == "" {
		return s
	}
	if ascii, err := idna.Lookup.ToASCII(s); err == nil {
		return ascii
	}
	return s
}

// canonicalURL normalizes a URL: scheme and host lowercased, default ports
// stripped, query-string keys sorted, fragment preserved. Unparseable values
// fall back to a trimmed string.
func canonicalURL(v string) string {
	s := strings.TrimSpace(v)
	u, err := url.Parse(s)
	if err != nil {
		return s
	}
	u.Scheme = strings.ToLower(u.Scheme)

	host := strings.ToLower(u.Hostname())
	if port := u.Port(); port != "" && !isDefaultPort(u.Scheme, port) {
		u.Host = net.JoinHostPort(host, port) // re-brackets IPv6 literals
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]" // IPv6 literal without a port keeps its brackets
	} else {
		u.Host = host
	}

	if u.RawQuery != "" {
		q := u.Query()
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		for i, k := range keys {
			vals := q[k]
			sort.Strings(vals)
			for j, val := range vals {
				if i > 0 || j > 0 {
					b.WriteByte('&')
				}
				b.WriteString(url.QueryEscape(k))
				b.WriteByte('=')
				b.WriteString(url.QueryEscape(val))
			}
		}
		u.RawQuery = b.String()
	}
	return u.String()
}

// canonicalMAC normalizes a MAC address to lowercase colon-separated form
// (net.HardwareAddr.String). Unparseable values fall back to lowercased input.
func canonicalMAC(v string) string {
	s := strings.TrimSpace(v)
	if hw, err := net.ParseMAC(s); err == nil {
		return hw.String()
	}
	return strings.ToLower(s)
}

// isDefaultPort reports whether port is the scheme's default (stripped from the
// canonical URL).
func isDefaultPort(scheme, port string) bool {
	switch scheme {
	case "http", "ws":
		return port == "80"
	case "https", "wss":
		return port == "443"
	case "ftp":
		return port == "21"
	default:
		return false
	}
}

// canonicalJSON serializes v deterministically for hashing. json.Marshal sorts
// map keys and preserves struct field order, so the same logical value always
// produces the same bytes. The identity-contributing values passed here are
// always JSON-serializable (strings, ints, and nested maps of the same), so the
// error path is unreachable in practice; it falls back to fmt.Sprintf only to
// keep the function total and panic-free.
func canonicalJSON(v any) []byte {
	if b, err := json.Marshal(v); err == nil {
		return b
	}
	return []byte(fmt.Sprintf("%v", v))
}

// contentHash returns the lowercase hex SHA-256 of v's canonical JSON. Used for
// ObservedData identity (hashing the OCSF payload).
func contentHash(v any) string {
	sum := sha256.Sum256(canonicalJSON(v))
	return hex.EncodeToString(sum[:])
}
