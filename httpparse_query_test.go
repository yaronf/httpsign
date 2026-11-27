package httpsign

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestWHATWGQueryCanonicalization(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		query string
		key   string
		value string
	}{
		{name: "malformed escape", query: "a=%zz", key: "a", value: "%25zz"},
		{name: "bare percent", query: "a=%", key: "a", value: "%25"},
		{name: "incomplete escape", query: "a=%2", key: "a", value: "%252"},
		{name: "mixed escapes", query: "a=%41%zz%42", key: "a", value: "A%25zzB"},
		{name: "semicolon in value", query: "a=x;y", key: "a", value: "x%3By"},
		{name: "semicolon in name", query: "a;b=x", key: "a%3Bb", value: "x"},
		{name: "invalid byte", query: "a=%FF", key: "a", value: "%EF%BF%BD"},
		{name: "consecutive invalid bytes", query: "a=%FF%FF", key: "a", value: "%EF%BF%BD%EF%BF%BD"},
		{name: "incomplete UTF-8", query: "a=%E2%82", key: "a", value: "%EF%BF%BD"},
		{name: "interrupted UTF-8", query: "a=%E2%82x", key: "a", value: "%EF%BF%BDx"},
		{name: "invalid continuation", query: "a=%E2%28%A1", key: "a", value: "%EF%BF%BD%28%EF%BF%BD"},
		{name: "overlong UTF-8", query: "a=%C0%AF", key: "a", value: "%EF%BF%BD%EF%BF%BD"},
		{name: "surrogate", query: "a=%ED%A0%80", key: "a", value: "%EF%BF%BD%EF%BF%BD%EF%BF%BD"},
		{name: "invalid raw UTF-8", query: "a=\xff", key: "a", value: "%EF%BF%BD"},
		{name: "invalid name", query: "%FF=x", key: "%EF%BF%BD", value: "x"},
		{name: "consecutive invalid name bytes", query: "%FF%FF=x", key: "%EF%BF%BD%EF%BF%BD", value: "x"},
		{name: "incomplete UTF-8 name", query: "%E2%82=x", key: "%EF%BF%BD", value: "x"},
		{name: "malformed name escape", query: "%zz=x", key: "%25zz", value: "x"},
		{name: "BOM preserved", query: "a=%EF%BB%BFx", key: "a", value: "%EF%BB%BFx"},
		{name: "valid UTF-8", query: "a=%C3%A9", key: "a", value: "%C3%A9"},
		{name: "plus and encoded plus", query: "a=+%2B%20", key: "a", value: "%20%2B%20"},
		{name: "space in name", query: "a+b=x", key: "a%20b", value: "x"},
		{name: "star and tilde", query: "a=*~", key: "a", value: "*%7E"},
		{name: "star and tilde in name", query: "*~=x", key: "*%7E", value: "x"},
		{name: "encoded star and tilde", query: "a=%2a%7e", key: "a", value: "*%7E"},
		{name: "decode once", query: "a=%2520", key: "a", value: "%2520"},
		{name: "first equals separates", query: "a=x=y", key: "a", value: "x%3Dy"},
		{name: "missing equals", query: "a", key: "a", value: ""},
		{name: "empty value", query: "a=", key: "a", value: ""},
		{name: "empty name", query: "=x", key: "", value: "x"},
		{name: "empty segments", query: "&&a=x&&", key: "a", value: "x"},
	}
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	config := NewVerifyConfig().SetVerifyCreated(false).SetRejectExpired(false)
	verifier, err := NewEd25519Verifier(privateKey.Public().(ed25519.PublicKey), config, Fields{})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			parameters := parseQueryForSignature(test.query)
			if len(parameters) != 1 || !slices.Equal(parameters[test.key], []string{test.value}) {
				t.Fatalf("parseQueryForSignature(%q) = %#v, want %q: [%q]", test.query, parameters, test.key, test.value)
			}
			request := httptest.NewRequest("GET", "https://example.com/", nil)
			request.URL.RawQuery = test.query
			input := fmt.Sprintf(`sig1=("@query" "@query-param";name="%s")`, test.key)
			signature, err := parseSignatureInput(input[len("sig1="):], "sig1")
			if err != nil {
				t.Fatal(err)
			}
			message, err := parseRequest(request, false, 0, "")
			if err != nil {
				t.Fatal(err)
			}
			base, err := generateSignatureBase(message, nil, signature.fields, signature.origSigParams)
			if err != nil {
				t.Fatal(err)
			}
			want := fmt.Sprintf("\"@query\": ?%s\n\"@query-param\";name=\"%s\": %s\n\"@signature-params\": (\"@query\" \"@query-param\";name=\"%s\")", test.query, test.key, test.value, test.key)
			if base != want {
				t.Fatalf("signature base = %q, want %q", base, want)
			}
			request.Header.Set("Signature-Input", input)
			request.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(want)))+":")
			if err := VerifyRequest("sig1", *verifier, request); err != nil {
				t.Fatalf("VerifyRequest() with independently constructed base: %v", err)
			}
		})
	}
}

func TestWHATWGQueryDuplicateDecodedNames(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		query string
		key   string
	}{
		{name: "literal duplicates", query: "a=first&a=second", key: "a"},
		{name: "escaped name", query: "a=first&%61=second", key: "a"},
		{name: "decoded spaces", query: "a+b=first&a%20b=second", key: "a%20b"},
		{name: "UTF-8 replacements", query: "%FF=first&%FE=second", key: "%EF%BF%BD"},
		{name: "incomplete UTF-8", query: "%E2%82=first&%EF%BF%BD=second", key: "%EF%BF%BD"},
		{name: "malformed escape", query: "%zz=first&%25zz=second", key: "%25zz"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			parameters := parseQueryForSignature(test.query)
			if len(parameters) != 1 || !slices.Equal(parameters[test.key], []string{"first", "second"}) {
				t.Fatalf("parseQueryForSignature(%q) = %#v, want %q: [first second]", test.query, parameters, test.key)
			}
		})
	}
}

func TestWHATWGQueryEmptySegments(t *testing.T) {
	t.Parallel()
	for _, query := range []string{"", "&", "&&&"} {
		if parameters := parseQueryForSignature(query); len(parameters) != 0 {
			t.Errorf("parseQueryForSignature(%q) = %#v, want no parameters", query, parameters)
		}
	}
}

func TestQueryEscapeForSignatureEncodeSet(t *testing.T) {
	t.Parallel()
	input := "a*-._Z9 !\"#$%&'()+,/:;<=>?@[\\]^`{|}~"
	want := "a*-._Z9%20%21%22%23%24%25%26%27%28%29%2B%2C%2F%3A%3B%3C%3D%3E%3F%40%5B%5C%5D%5E%60%7B%7C%7D%7E"
	if got := QueryEscapeForSignature(input); got != want {
		t.Errorf("QueryEscapeForSignature(%q) = %q, want %q", input, got, want)
	}
}
