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

func TestScRequestTarget(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		u    *url.URL
		want string
	}{
		{
			name: "plain path",
			u:    mustParseURL(t, "https://example.com/foo"),
			want: "/foo",
		},
		{
			name: "path with query",
			u:    mustParseURL(t, "https://example.com/foo?a=b"),
			want: "/foo?a=b",
		},
		{
			name: "escaped slash in path preserved",
			u:    mustParseURL(t, "https://example.com/a%2Fb"),
			want: "/a%2Fb",
		},
		{
			name: "escaped space in path preserved",
			u:    mustParseURL(t, "https://example.com/a%20b"),
			want: "/a%20b",
		},
		{
			name: "escaped path with query",
			u:    mustParseURL(t, "https://example.com/a%2Fb?x=1"),
			want: "/a%2Fb?x=1",
		},
		{
			name: "empty query delimiter preserved",
			u:    mustParseURL(t, "https://example.com/path?"),
			want: "/path?",
		},
		{
			name: "escaped path with empty query delimiter",
			u:    mustParseURL(t, "https://example.com/a%2Fb?"),
			want: "/a%2Fb?",
		},
		{
			name: "empty path normalized to slash",
			u:    mustParseURL(t, "https://example.com"),
			want: "/",
		},
		{
			name: "empty path with empty query delimiter",
			u:    mustParseURL(t, "https://example.com?"),
			want: "/?",
		},
		{
			name: "raw path set without re-encoding via Path alone",
			u:    &url.URL{Path: "/a/b", RawPath: "/a%2Fb"},
			want: "/a%2Fb",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, scRequestTarget(tc.u))
		})
	}
}

func TestScPath(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		u    *url.URL
		want string
	}{
		{name: "plain path", u: mustParseURL(t, "https://example.com/foo"), want: "/foo"},
		{name: "escaped slash preserved", u: mustParseURL(t, "https://example.com/a%2Fb"), want: "/a%2Fb"},
		{name: "query ignored", u: mustParseURL(t, "https://example.com/foo?a=b"), want: "/foo"},
		{name: "empty query delimiter ignored", u: mustParseURL(t, "https://example.com/path?"), want: "/path"},
		{name: "empty path normalized to slash", u: mustParseURL(t, "https://example.com"), want: "/"},
		{name: "raw path preserved", u: &url.URL{Path: "/a/b", RawPath: "/a%2Fb"}, want: "/a%2Fb"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, scPath(tc.u))
		})
	}
}

func TestDerivedRequestTarget(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		raw      string
		wantRT   string
		wantPath string
	}{
		{name: "escaped slash", raw: "https://example.com/a%2Fb", wantRT: "/a%2Fb", wantPath: "/a%2Fb"},
		{name: "empty query", raw: "https://example.com/path?", wantRT: "/path?", wantPath: "/path"},
		{name: "escaped slash and empty query", raw: "https://example.com/a%2Fb?", wantRT: "/a%2Fb?", wantPath: "/a%2Fb"},
		{name: "normal query", raw: "https://example.com/foo?a=b", wantRT: "/foo?a=b", wantPath: "/foo"},
		{name: "empty path", raw: "https://example.com", wantRT: "/", wantPath: "/"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", tc.raw, nil)
			require.NoError(t, err)
			msg, err := parseRequest(req, false, 0, "https")
			require.NoError(t, err)
			assert.Equal(t, tc.wantRT, msg.derived["@request-target"])
			assert.Equal(t, tc.wantPath, msg.derived["@path"])
		})
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
}
