package httpsign

import (
	"encoding/base64"
	"net/http"
	"net/url"
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
		{name: "ipv4-mapped ipv6 default https port", scheme: "https", authority: "[::ffff:192.0.2.1]:443", want: "[::ffff:192.0.2.1]"},
		{name: "ipv6 zone id default https port", scheme: "https", authority: "[fe80::1%eth0]:443", want: "[fe80::1%eth0]"},
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
		name     string
		url      string
		host     string
		scheme   string
		wantAuth string
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

func TestScScheme(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		u    *url.URL
		want string
	}{
		{name: "empty defaults to http", u: &url.URL{}, want: "http"},
		{name: "http lowercase", u: &url.URL{Scheme: "http"}, want: "http"},
		{name: "https lowercase", u: &url.URL{Scheme: "https"}, want: "https"},
		{name: "HTTP upper", u: &url.URL{Scheme: "HTTP"}, want: "http"},
		{name: "HTTPS upper", u: &url.URL{Scheme: "HTTPS"}, want: "https"},
		{name: "Https mixed", u: &url.URL{Scheme: "Https"}, want: "https"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, scScheme(tc.u))
		})
	}
}

func TestDerivedSchemeLowercase(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name           string
		url            string
		schemeOverride string
		want           string
	}{
		{name: "https from URL", url: "https://example.com/x", schemeOverride: "", want: "https"},
		{name: "override HTTPS folded", url: "http://example.com/x", schemeOverride: "HTTPS", want: "https"},
		{name: "override HTTP folded", url: "https://example.com/x", schemeOverride: "HTTP", want: "http"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", tc.url, nil)
			require.NoError(t, err)
			if tc.schemeOverride != "" {
				req.URL.Scheme = ""
			}
			msg, err := parseRequest(req, false, 0, tc.schemeOverride)
			require.NoError(t, err)
			assert.Equal(t, tc.want, msg.derived["@scheme"])
		})
	}
}

func TestSchemeFromRequestFoldedInSignatureBase(t *testing.T) {
	t.Parallel()

	req, err := http.NewRequest("GET", "http://example.com/x", nil)
	require.NoError(t, err)
	req.URL.Scheme = ""

	key, err := base64.StdEncoding.DecodeString("uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==")
	require.NoError(t, err)

	fields := Headers("@scheme")
	signer, err := NewHMACSHA256Signer(key,
		NewSignConfig().SignCreated(false).SignAlg(false).SetSchemeFromRequest(func(*http.Request) string {
			return "HTTPS"
		}),
		fields)
	require.NoError(t, err)

	_, _, base, err := signRequestDebug("sig1", *signer, req)
	require.NoError(t, err)
	assert.Contains(t, base, `"@scheme": https`)
	assert.NotContains(t, base, `"@scheme": HTTPS`)
}
