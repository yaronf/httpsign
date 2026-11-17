package httpsign

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
