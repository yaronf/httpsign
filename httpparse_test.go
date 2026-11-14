package httpsign

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
