package httpsign

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"github.com/andreyvit/diff"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"text/template"
)

var wantFields = `"kuku": my awesome header
"@query": ?k1=v1&k2
"@method": GET
"@target-uri": {{.Scheme}}://127.0.0.1:{{.Port}}/path?k1=v1&k2
"@authority": 127.0.0.1:{{.Port}}
"@scheme": {{.Scheme}}
"@target-uri": {{.Scheme}}://127.0.0.1:{{.Port}}/path?k1=v1&k2
"@path": /path
"@query": ?k1=v1&k2
"@query-params";name="k1": v1
"@query-params";name="k2": 
"@signature-params": ("kuku" "@query" "@method" "@target-uri" "@authority" "@scheme" "@target-uri" "@path" "@query" "@query-params";name="k1" "@query-params";name="k2");alg="hmac-sha256";keyid="key1"`

func execTemplate(t template.Template, name string, data interface{}) (string, error) {
	buf := &bytes.Buffer{}
	err := t.ExecuteTemplate(buf, name, data)
	return buf.String(), err
}

func newClientRequest(t *testing.T, method, url, body string) *http.Request {
	in := strings.NewReader(body)
	req, err := http.NewRequest(method, url, bufio.NewReader(in))
	if err != nil {
		t.Errorf("could not read request")
	}
	return req
}

var ts *httptest.Server // global, so can be used *inside* the server, too

func testHTTP(t *testing.T, proto string) {
	simpleHandler := func(w http.ResponseWriter, r *http.Request) {
		reqProto := r.Proto
		if reqProto != proto {
			t.Errorf("expected %s, got %s", proto, reqProto)
		}
		var scheme string
		if ts.TLS == nil {
			scheme = "http"
		} else {
			scheme = "https"
		}
		sp := bytes.Split([]byte(ts.URL), []byte(":"))
		portval, err := strconv.Atoi(string(sp[2]))
		if err != nil {
			t.Errorf("cannot parse server port number")
		}
		tpl, err := template.New("fields").Parse(wantFields)
		if err != nil {
			t.Errorf("could not parse template")
		}
		type inputs struct {
			Port   int
			Scheme string
		}
		wf, err := execTemplate(*tpl, "fields", inputs{Port: portval, Scheme: scheme})
		verifier, err := NewHMACSHA256Verifier("key1", bytes.Repeat([]byte{0x03}, 64),
			NewVerifyConfig().SetVerifyCreated(false),
			Headers("@query"))
		if err != nil {
			t.Errorf("could not create verifier")
		}
		sigInput, err := verifyRequestDebug("sig1", *verifier, r)
		if err != nil {
			t.Errorf("failed to verify request: sig input: %s\nerr: %v", sigInput, err)
		}

		if sigInput != wf {
			// t.Errorf("expected: %s\ngot: %s\n", wantFields, sigInput)
			t.Errorf("unexpected fields: %s\n", diff.CharacterDiff(sigInput, wantFields))
		}
		w.WriteHeader(200)
	}

	// Client code
	switch proto {
	case "HTTP/1.1":
		ts = httptest.NewServer(http.HandlerFunc(simpleHandler))
	case "HTTP/2.0":
		ts = httptest.NewUnstartedServer(http.HandlerFunc(simpleHandler))
		ts.EnableHTTP2 = true
		ts.StartTLS()
	default:
		t.Errorf("no server")
	}
	defer ts.Close()

	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // Do not verify server certificate
		ForceAttemptHTTP2: true,
	}

	signer, err := NewHMACSHA256Signer("key1", bytes.Repeat([]byte{0x03}, 64),
		NewSignConfig().SignCreated(false),
		*NewFields().AddHeaders("kuku", "@query", "@method", "@target-uri", "@authority", "@scheme", "@target-uri",
			"@path", "@query").AddQueryParam("k1").AddQueryParam("k2"))
	var client *Client
	switch proto {
	case "HTTP/1.1":
		client = NewDefaultClient("sig1", signer, nil, nil)
	case "HTTP/2.0":
		c := &http.Client{Transport: tr}
		client = NewClient("sig1", signer, nil, nil, *c)
	default:
		t.Errorf("no client for you")
	}
	req := newClientRequest(t, "GET", ts.URL+"/path"+"?k1=v1&k2", "")
	req.Header.Set("Kuku", "my awesome header")
	res, err := client.Do(req)
	if err != nil {
		t.Errorf("%v", err)
	}
	if res != nil {
		_, err = io.ReadAll(res.Body)
		_ = res.Body.Close()
		if err != nil {
			t.Errorf("%v", err)
		}

		if res.Status != "200 OK" {
			t.Errorf("Bad status returned")
		}
	}
}

func TestHTTP11(t *testing.T) {
	testHTTP(t, "HTTP/1.1")
}

func TestHTTP20(t *testing.T) {
	testHTTP(t, "HTTP/2.0")
}
