package httpsign

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestClient_Get(t *testing.T) {
	type fields struct {
		sigName       string
		signer        *Signer
		verifier      *Verifier
		fetchVerifier func(res *http.Response, req *http.Request) (sigName string, verifier *Verifier)
		Client        http.Client
	}
	type args struct {
		url string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantRes string
		wantErr bool
	}{
		{
			name: "Happy path",
			fields: fields{
				sigName: "sig1",
				signer: func() *Signer {
					signer, _ := NewHMACSHA256Signer("key1", bytes.Repeat([]byte{1}, 64), NewSignConfig(), HeaderList([]string{"@method"}))
					return signer
				}(),
				verifier:      nil,
				fetchVerifier: nil,
				Client:        *http.DefaultClient,
			},
			args: args{
				url: "",
			},
			wantRes: "200 OK",
			wantErr: false,
		},
		{
			name: "not found",
			fields: fields{
				sigName: "sig1",
				signer: func() *Signer {
					signer, _ := NewHMACSHA256Signer("key1", bytes.Repeat([]byte{1}, 64), NewSignConfig(), HeaderList([]string{"@method"}))
					return signer
				}(),
				verifier:      nil,
				fetchVerifier: nil,
				Client:        *http.DefaultClient,
			},
			args: args{
				url: "/thisaintaurl",
			},
			wantRes: "404 Not Found",
			wantErr: false,
		},
		{
			name: "bad signature name",
			fields: fields{
				sigName: "",
				signer: func() *Signer {
					signer, _ := NewHMACSHA256Signer("key1", bytes.Repeat([]byte{1}, 64), NewSignConfig(), HeaderList([]string{"@method"}))
					return signer
				}(),
				verifier:      nil,
				fetchVerifier: nil,
				Client:        *http.DefaultClient,
			},
			args: args{
				url: "",
			},
			wantRes: "",
			wantErr: true,
		},
		{
			name: "bad fetch verifier",
			fields: fields{
				sigName: "sig1",
				signer: func() *Signer {
					signer, _ := NewHMACSHA256Signer("key1", bytes.Repeat([]byte{1}, 64), NewSignConfig(), HeaderList([]string{"@method"}))
					return signer
				}(),
				verifier: nil,
				fetchVerifier: func(res *http.Response, req *http.Request) (sigName string, verifier *Verifier) {
					return "name", nil
				},
				Client: *http.DefaultClient,
			},
			args: args{
				url: "",
			},
			wantRes: "",
			wantErr: true,
		},
		{
			name: "verifier fails",
			fields: fields{
				sigName: "sig1",
				signer: func() *Signer {
					signer, _ := NewHMACSHA256Signer("key1", bytes.Repeat([]byte{1}, 64), NewSignConfig(), HeaderList([]string{"@method"}))
					return signer
				}(),
				verifier: nil,
				fetchVerifier: func(res *http.Response, req *http.Request) (sigName string, verifier *Verifier) {
					verifier, _ = NewHMACSHA256Verifier("key1", bytes.Repeat([]byte{2}, 64), NewVerifyConfig(), HeaderList([]string{"@method"}))
					return "name", verifier
				},
				Client: *http.DefaultClient,
			},
			args: args{
				url: "",
			},
			wantRes: "",
			wantErr: true,
		},
	}

	ts := makeTestServer()
	defer ts.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				SignatuerName: tt.fields.sigName,
				Signer:        tt.fields.signer,
				Verifier:      tt.fields.verifier,
				FetchVerifier: tt.fields.fetchVerifier,
				Client:        tt.fields.Client,
			}
			res, err := c.Get(ts.URL + tt.args.url)
			var gotRes string
			if res != nil {
				gotRes = res.Status
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotRes, tt.wantRes) {
				t.Errorf("Get() gotRes = %v, want %v", gotRes, tt.wantRes)
			}
		})
	}
}

func makeTestServer() *httptest.Server {
	simpleHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI == "/" {
			w.WriteHeader(200)
		} else {
			w.WriteHeader(404)
		}
		_, err := fmt.Fprintln(w, "Hey client, good to see ya")
		if err != nil {
			log.Fatal("Server could not send response")
		}
	}
	ts := httptest.NewServer(http.HandlerFunc(simpleHandler))
	return ts
}

func TestClient_Head(t *testing.T) {
	type fields struct {
		sigName       string
		signer        *Signer
		verifier      *Verifier
		fetchVerifier func(res *http.Response, req *http.Request) (sigName string, verifier *Verifier)
		Client        http.Client
	}
	type args struct {
		url string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantRes string
		wantErr bool
	}{
		{
			name: "TLS",
			fields: fields{
				sigName: "sig1",
				signer: func() *Signer {
					signer, _ := NewHMACSHA256Signer("key1", bytes.Repeat([]byte{1}, 64), NewSignConfig(), HeaderList([]string{"@method"}))
					return signer
				}(),
				verifier:      nil,
				fetchVerifier: nil,
				Client:        *http.DefaultClient,
			},
			args: args{
				url: "/",
			},
			wantRes: "200 OK",
			wantErr: false,
		},
	}

	ts := makeTestServer()
	defer ts.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				SignatuerName: tt.fields.sigName,
				Signer:        tt.fields.signer,
				Verifier:      tt.fields.verifier,
				FetchVerifier: tt.fields.fetchVerifier,
				Client:        tt.fields.Client,
			}

			res, err := c.Head(ts.URL + tt.args.url)
			var gotRes string
			if res != nil {
				gotRes = res.Status
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("Head() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotRes, tt.wantRes) {
				t.Errorf("Head() gotRes = %v, want %v", gotRes, tt.wantRes)
			}
		})
	}
}
