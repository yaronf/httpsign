package httpsign

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/lestrrat-go/jwx/jwa"
	"reflect"
	"strings"
	"testing"
)

func TestNewHMACSHA256Signer(t *testing.T) {
	type args struct {
		keyID string
		key   []byte
		c     *SignConfig
		f     Fields
	}
	tests := []struct {
		name    string
		args    args
		want    *Signer
		wantErr bool
	}{
		{
			name: "happy path",
			args: args{
				keyID: "key1",
				key:   []byte(strings.Repeat("c", 64)),
				c:     nil,
				f:     Fields{},
			},
			want: &Signer{
				keyID:  "key1",
				key:    []byte(strings.Repeat("c", 64)),
				alg:    "hmac-sha256",
				config: NewSignConfig(),
				fields: Fields{},
			},
			wantErr: false,
		},
		{
			name: "key too short",
			args: args{
				keyID: "key2",
				key:   []byte("abc"),
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewHMACSHA256Signer(tt.args.keyID, tt.args.key, tt.args.c, tt.args.f)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewHMACSHA256Signer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewHMACSHA256Signer() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigner_sign(t *testing.T) {
	type fields struct {
		keyID string
		key   interface{}
		alg   string
	}
	type args struct {
		buff []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "happy path",
			fields: fields{
				keyID: "key1",
				key:   []byte(strings.Repeat("a", 64)),
				alg:   "hmac-sha256",
			},
			args: args{
				buff: []byte("abc"),
			},
			want:    []byte{102, 8, 172, 130, 220, 161, 203, 31, 221, 187, 93, 129, 227, 217, 135, 118, 66, 183, 68, 245, 101, 205, 150, 151, 172, 39, 218, 162, 80, 200, 13, 40},
			wantErr: false,
		},
		{
			name: "bad alg",
			fields: fields{
				keyID: "key1",
				key:   []byte(strings.Repeat("a", 64)),
				alg:   "hmac-sha999",
			},
			args: args{
				buff: []byte("abc"),
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Signer{
				keyID: tt.fields.keyID,
				key:   tt.fields.key,
				alg:   tt.fields.alg,
			}
			got, err := s.sign(tt.args.buff)
			if (err != nil) != tt.wantErr {
				t.Errorf("sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("sign() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewRSASigner(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Errorf("failed to gen private key")
	}
	_ = privateKey.Public()

	type args struct {
		keyID  string
		key    *rsa.PrivateKey
		config *SignConfig
		fields Fields
	}
	tests := []struct {
		name    string
		args    args
		want    *Signer
		wantErr bool
	}{
		{
			name: "empty key ID",
			args: args{
				keyID:  "",
				key:    privateKey,
				config: nil,
				fields: nil,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "nil key",
			args: args{
				keyID:  "kk",
				key:    nil,
				config: NewSignConfig(),
				fields: nil,
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewRSASigner(tt.args.keyID, tt.args.key, tt.args.config, tt.args.fields)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRSASigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRSASigner() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestForeignSigner(t *testing.T) {
	priv, pub, err := genP256KeyPair()
	if err != nil {
		t.Errorf("Failed to generate keypair: %v", err)
	}

	config := NewSignConfig().setFakeCreated(1618884475)
	signatureName := "sig1"
	fields := *NewFields().AddHeader("@method").AddHeader("date").AddHeader("content-type").AddQueryParam("pet")
	signer, err := NewJWSSigner(jwa.ES256, "key1", priv, config, fields)
	if err != nil {
		t.Errorf("Failed to create JWS signer")
	}
	req := readRequest(httpreq2)
	sigInput, sig, err := SignRequest(signatureName, *signer, req)
	if err != nil {
		t.Errorf("signature failed: %v", err)
	}
	req.Header.Add("Signature", sig)
	req.Header.Add("Signature-Input", sigInput)
	verifier, err := NewJWSVerifier(jwa.ES256, pub, "key1", NewVerifyConfig().SetVerifyCreated(false), fields)
	if err != nil {
		t.Errorf("could not generate Verifier: %s", err)
	}
	err = VerifyRequest(signatureName, *verifier, req)
	if err != nil {
		t.Errorf("verification error: %s", err)
	}
}
