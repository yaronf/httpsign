package httpsign

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCanonicalAuthority(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		scheme    string
		authority string
		want      string
	}{
		{name: "lowercase host", scheme: "https", authority: "EXAMPLE.com", want: "example.com"},
		{name: "https default port omitted", scheme: "https", authority: "EXAMPLE.com:443", want: "example.com"},
		{name: "http default port omitted", scheme: "http", authority: "EXAMPLE.com:80", want: "example.com"},
		{name: "https non-default port kept", scheme: "https", authority: "example.com:8443", want: "example.com:8443"},
		{name: "http non-default port kept", scheme: "http", authority: "example.com:8080", want: "example.com:8080"},
		{name: "https non-default port case fold", scheme: "https", authority: "EXAMPLE.com:8443", want: "example.com:8443"},
		{name: "http non-default port case fold", scheme: "http", authority: "EXAMPLE.com:8080", want: "example.com:8080"},
		{name: "http with 443 kept", scheme: "http", authority: "example.com:443", want: "example.com:443"},
		{name: "https with 80 kept", scheme: "https", authority: "example.com:80", want: "example.com:80"},
		{name: "scheme case insensitive", scheme: "HTTPS", authority: "Example.COM:443", want: "example.com"},
		{name: "ipv4 no port", scheme: "https", authority: "192.0.2.10", want: "192.0.2.10"},
		{name: "ipv4 https default port omitted", scheme: "https", authority: "192.0.2.10:443", want: "192.0.2.10"},
		{name: "ipv4 http default port omitted", scheme: "http", authority: "192.0.2.10:80", want: "192.0.2.10"},
		{name: "ipv4 https non-default port", scheme: "https", authority: "192.0.2.10:8443", want: "192.0.2.10:8443"},
		{name: "ipv4 http non-default port", scheme: "http", authority: "192.0.2.10:8080", want: "192.0.2.10:8080"},
		{name: "ipv6 default https port", scheme: "https", authority: "[2001:db8::1]:443", want: "[2001:db8::1]"},
		{name: "ipv6 default http port", scheme: "http", authority: "[2001:db8::1]:80", want: "[2001:db8::1]"},
		{name: "ipv6 hextet 443 unchanged", scheme: "https", authority: "[2001:db8::443]", want: "[2001:db8::443]"},
		{name: "ipv6 hextet 80 unchanged", scheme: "http", authority: "[2001:db8::80]", want: "[2001:db8::80]"},
		{name: "ipv6 https non-default port", scheme: "https", authority: "[2001:db8::1]:8443", want: "[2001:db8::1]:8443"},
		{name: "ipv6 http non-default port", scheme: "http", authority: "[2001:db8::1]:8080", want: "[2001:db8::1]:8080"},
		{name: "empty", scheme: "https", authority: "", want: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, canonicalAuthority(tc.scheme, tc.authority))
		})
	}
}

func TestDerivedAuthorityNonDefaultPort(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		url       string
		host      string
		scheme    string
		wantAuth  string
	}{
		{
			name:     "https custom port",
			url:      "https://example.com:8443/path",
			host:     "EXAMPLE.com:8443",
			scheme:   "https",
			wantAuth: "example.com:8443",
		},
		{
			name:     "http custom port",
			url:      "http://example.com:8080/path",
			host:     "EXAMPLE.com:8080",
			scheme:   "http",
			wantAuth: "example.com:8080",
		},
		{
			name:     "https default port still omitted",
			url:      "https://example.com/path",
			host:     "EXAMPLE.com:443",
			scheme:   "https",
			wantAuth: "example.com",
		},
		{
			name:     "ipv4 https custom port",
			url:      "https://192.0.2.10:8443/path",
			host:     "192.0.2.10:8443",
			scheme:   "https",
			wantAuth: "192.0.2.10:8443",
		},
		{
			name:     "ipv4 https default port omitted",
			url:      "https://192.0.2.10/path",
			host:     "192.0.2.10:443",
			scheme:   "https",
			wantAuth: "192.0.2.10",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", tc.url, nil)
			require.NoError(t, err)
			req.Host = tc.host
			msg, err := parseRequest(req, false, 0, tc.scheme)
			require.NoError(t, err)
			assert.Equal(t, tc.wantAuth, msg.derived["@authority"])
		})
	}
}
