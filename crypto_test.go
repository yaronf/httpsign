package httpsign

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/stretchr/testify/assert"
)

func TestNewHMACSHA256Signer(t *testing.T) {
	type args struct {
		key []byte
		c   *SignConfig
		f   Fields
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
				key: []byte(strings.Repeat("c", 64)),
				c:   nil,
				f:   Fields{},
			},
			want: &Signer{
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
				key: []byte("abc"),
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewHMACSHA256Signer(tt.args.key, tt.args.c, tt.args.f)
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
		key interface{}
		alg string
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
				key: []byte(strings.Repeat("a", 64)),
				alg: "hmac-sha256",
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
				key: []byte(strings.Repeat("a", 64)),
				alg: "hmac-sha999",
			},
			args: args{
				buff: []byte("abc"),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "ed25519 key not 64 bytes",
			fields: fields{
				key: ed25519.PrivateKey(strings.Repeat("a", 63)),
				alg: "ed25519",
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
				key: tt.fields.key,
				alg: tt.fields.alg,
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

func TestForeignSigner(t *testing.T) {
	priv, pub, err := genP256KeyPair()
	if err != nil {
		t.Errorf("Failed to generate keypair: %v", err)
	}

	config := NewSignConfig().setFakeCreated(1618884475).SignAlg(false)
	signatureName := "sig1"
	fields := *NewFields().AddHeader("@method").AddHeader("date").AddHeader("content-type").AddQueryParam("pet")
	signer, err := NewJWSSigner(jwa.ES256, priv, config.SetKeyID("key1"), fields)
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
	verifier, err := NewJWSVerifier(jwa.ES256, pub, NewVerifyConfig().SetVerifyCreated(false).SetKeyID("key1"), fields)
	if err != nil {
		t.Errorf("could not generate Verifier: %s", err)
	}
	err = VerifyRequest(signatureName, *verifier, req)
	if err != nil {
		t.Errorf("verification error: %s", err)
	}
}

// Same as TestForeignSigner but using Message
func TestMessageForeignSigner(t *testing.T) {
	priv, pub, err := genP256KeyPair()
	if err != nil {
		t.Errorf("Failed to generate keypair: %v", err)
	}

	config := NewSignConfig().setFakeCreated(1618884475).SignAlg(false)
	signatureName := "sig1"
	fields := *NewFields().AddHeader("@method").AddHeader("date").AddHeader("content-type").AddQueryParam("pet")
	signer, err := NewJWSSigner(jwa.ES256, priv, config.SetKeyID("key1"), fields)
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
	verifier, err := NewJWSVerifier(jwa.ES256, pub, NewVerifyConfig().SetVerifyCreated(false).SetKeyID("key1"), fields)
	if err != nil {
		t.Errorf("could not generate Verifier: %s", err)
	}
	msg, err := NewMessage(NewMessageConfig().WithRequest(req))
	if err != nil {
		t.Errorf("Failed to create Message")
	}
	_, err = msg.Verify(signatureName, *verifier)
	if err != nil {
		t.Errorf("verification error: %s", err)
	}
}

func makeRSAPrivateKey() *rsa.PrivateKey {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	return priv
}
func TestNewRSASigner1(t *testing.T) {
	type args struct {
		keyID  string
		key    *rsa.PrivateKey
		config *SignConfig
		fields Fields
	}
	key := makeRSAPrivateKey()
	tests := []struct {
		name    string
		args    args
		want    *Signer
		wantErr bool
	}{
		{
			name: "happy path",
			args: args{
				key:    key,
				config: nil,
				fields: *NewFields(),
			},
			want: &Signer{
				key:           *key,
				alg:           "rsa-v1_5-sha256",
				config:        NewSignConfig(),
				fields:        Fields{},
				foreignSigner: nil,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewRSASigner(*tt.args.key, tt.args.config, tt.args.fields)
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

func TestNewJWSVerifier(t *testing.T) {
	type args struct {
		alg    jwa.SignatureAlgorithm
		key    interface{}
		keyID  string
		config *VerifyConfig
		fields Fields
	}
	verifier, _ := jws.NewVerifier("HS256")
	tests := []struct {
		name    string
		args    args
		want    *Verifier
		wantErr bool
	}{
		{
			name: "happy path",
			args: args{
				alg:    jwa.SignatureAlgorithm("HS256"),
				key:    "1234",
				keyID:  "key200",
				config: nil,
				fields: *NewFields(),
			},
			want: &Verifier{
				key:             "1234",
				alg:             "",
				config:          NewVerifyConfig(),
				fields:          *NewFields(),
				foreignVerifier: verifier,
			},
			wantErr: false,
		},
		{
			name: "none",
			args: args{
				alg:    jwa.NoSignature,
				key:    "1234",
				keyID:  "key200",
				config: NewVerifyConfig(),
				fields: *NewFields(),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "bad verifier",
			args: args{
				alg:    jwa.SignatureAlgorithm("bad"),
				key:    "1234",
				keyID:  "key200",
				config: NewVerifyConfig(),
				fields: *NewFields(),
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewJWSVerifier(tt.args.alg, tt.args.key, tt.args.config, tt.args.fields)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewJWSVerifier() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil {
				got.foreignVerifier = nil
			}
			if tt.want != nil {
				tt.want.foreignVerifier = nil
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewJWSVerifier() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	v := Verifier{
		key:             nil,
		alg:             "bad-alg",
		config:          NewVerifyConfig(),
		fields:          Fields{},
		foreignVerifier: nil,
	}
	_, err := v.verify([]byte{1, 2, 3}, []byte{4, 5, 6})
	assert.ErrorContains(t, err, "unknown", "bad algorithm")

	v.alg = "hmac-sha256"
	v.foreignVerifier = struct{ xx int }{7}
	_, err = v.verify([]byte{1, 2, 3}, []byte{4, 5, 6})
	assert.ErrorContains(t, err, "expected", "bad algorithm")
}
