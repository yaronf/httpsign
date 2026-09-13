package httpsign

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		key any
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
	signer, err := NewJWSSigner(jwa.ES256(), priv, config.SetKeyID("key1"), fields)
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
	verifier, err := NewJWSVerifier(nil, pub, NewVerifyConfig().SetVerifyCreated(false).SetKeyID("key1"), fields)
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
	signer, err := NewJWSSigner(jwa.ES256(), priv, config.SetKeyID("key1"), fields)
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
	verifier, err := NewJWSVerifier(nil, pub, NewVerifyConfig().SetVerifyCreated(false).SetKeyID("key1"), fields)
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

func TestNewJWSSigner(t *testing.T) {
	hmacKey := []byte(strings.Repeat("x", 32)) // RFC 7518 HS256 minimum
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	mldsa44, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)

	tests := []struct {
		name    string
		alg     jwa.SignatureAlgorithm
		key     any
		wantErr bool
	}{
		{name: "happy path", alg: jwa.HS256(), key: hmacKey},
		{name: "handcrafted registered name", alg: jwa.NewSignatureAlgorithm("HS256"), key: hmacKey},
		{name: "none", alg: jwa.NoSignature(), key: hmacKey, wantErr: true},
		{name: "empty alg", alg: jwa.EmptySignatureAlgorithm(), key: hmacKey, wantErr: true},
		{name: "handcrafted NONE", alg: jwa.NewSignatureAlgorithm("NONE"), key: hmacKey, wantErr: true},
		{name: "unregistered alg", alg: jwa.NewSignatureAlgorithm("totally-made-up"), key: hmacKey, wantErr: true},
		{name: "nil key", alg: jwa.HS256(), key: nil, wantErr: true},
		{name: "string hmac key", alg: jwa.HS256(), key: "1234", wantErr: true},
		{name: "short hmac key", alg: jwa.HS256(), key: []byte("too-short"), wantErr: true},
		{name: "empty hmac key", alg: jwa.HS256(), key: []byte{}, wantErr: true},
		{name: "key alg mismatch", alg: jwa.HS256(), key: priv, wantErr: true},
		{name: "rsa match", alg: jwa.RS256(), key: priv},
		{name: "rsa public key", alg: jwa.RS256(), key: &priv.PublicKey, wantErr: true},
		{name: "ecdsa curve match", alg: jwa.ES256(), key: p256},
		{name: "ecdsa public key", alg: jwa.ES256(), key: &p256.PublicKey, wantErr: true},
		{name: "ecdsa curve mismatch", alg: jwa.ES384(), key: p256, wantErr: true},
		{name: "ecdsa nil curve", alg: jwa.ES256(), key: ecdsa.PrivateKey{}, wantErr: true},
		{name: "mldsa params match", alg: jwa.MLDSA44(), key: mldsa44},
		{name: "mldsa public key", alg: jwa.MLDSA44(), key: mldsa44.Public().(*mldsa.PublicKey), wantErr: true},
		{name: "mldsa params mismatch", alg: jwa.MLDSA65(), key: mldsa44, wantErr: true},
		{name: "mldsa wrong key type", alg: jwa.MLDSA44(), key: p256, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewJWSSigner(tt.alg, tt.key, nil, *NewFields())
			if tt.wantErr {
				require.Error(t, err)
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			require.NotNil(t, got.foreignSigner)
			assert.Equal(t, tt.key, got.key)
			assert.Empty(t, got.alg)
		})
	}
}

func TestNewJWSVerifierWithAlg(t *testing.T) {
	hmacKey := []byte(strings.Repeat("x", 32)) // RFC 7518 HS256 minimum
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	mldsa44, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)

	type args struct {
		alg    jwa.SignatureAlgorithm
		key    any
		config *VerifyConfig
		fields Fields
	}
	tests := []struct {
		name    string
		args    args
		want    *Verifier
		wantErr bool
	}{
		{
			name: "happy path",
			args: args{
				alg:    jwa.HS256(),
				key:    hmacKey,
				config: nil,
				fields: *NewFields(),
			},
			want: &Verifier{
				key:             hmacKey,
				alg:             "",
				config:          NewVerifyConfig(),
				fields:          *NewFields(),
				foreignVerifier: nil, // cleared below
			},
			wantErr: false,
		},
		{
			name: "none",
			args: args{
				alg:    jwa.NoSignature(),
				key:    hmacKey,
				config: NewVerifyConfig(),
				fields: *NewFields(),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "empty alg",
			args: args{
				alg:    jwa.EmptySignatureAlgorithm(),
				key:    hmacKey,
				config: NewVerifyConfig(),
				fields: *NewFields(),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "handcrafted NONE",
			args: args{
				alg:    jwa.NewSignatureAlgorithm("NONE"),
				key:    hmacKey,
				config: NewVerifyConfig(),
				fields: *NewFields(),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "unregistered alg",
			args: args{
				alg:    jwa.NewSignatureAlgorithm("totally-made-up"),
				key:    hmacKey,
				config: NewVerifyConfig(),
				fields: *NewFields(),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "handcrafted registered name",
			args: args{
				alg:    jwa.NewSignatureAlgorithm("HS256"),
				key:    hmacKey,
				config: NewVerifyConfig(),
				fields: *NewFields(),
			},
			want: &Verifier{
				key:             hmacKey,
				alg:             "",
				config:          NewVerifyConfig(),
				fields:          *NewFields(),
				foreignVerifier: nil,
			},
			wantErr: false,
		},
		{
			name: "nil key",
			args: args{
				alg:    jwa.HS256(),
				key:    nil,
				config: NewVerifyConfig(),
				fields: *NewFields(),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "string hmac key",
			args: args{
				alg:    jwa.HS256(),
				key:    "1234",
				config: NewVerifyConfig(),
				fields: *NewFields(),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "key alg mismatch",
			args: args{
				alg:    jwa.HS256(),
				key:    priv.Public(),
				config: NewVerifyConfig(),
				fields: *NewFields(),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "rsa private key",
			args: args{
				alg:    jwa.RS256(),
				key:    priv,
				config: NewVerifyConfig(),
				fields: *NewFields(),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "ecdsa curve match",
			args: args{
				alg:    jwa.ES256(),
				key:    &p256.PublicKey,
				config: NewVerifyConfig(),
				fields: *NewFields(),
			},
			want: &Verifier{
				key:             &p256.PublicKey,
				alg:             "",
				config:          NewVerifyConfig(),
				fields:          *NewFields(),
				foreignVerifier: nil,
			},
		},
		{
			name: "ecdsa curve mismatch",
			args: args{
				alg:    jwa.ES384(),
				key:    &p256.PublicKey,
				config: NewVerifyConfig(),
				fields: *NewFields(),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "ecdsa private key",
			args: args{
				alg:    jwa.ES256(),
				key:    p256,
				config: NewVerifyConfig(),
				fields: *NewFields(),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "mldsa params match",
			args: args{
				alg:    jwa.MLDSA44(),
				key:    mldsa44.Public().(*mldsa.PublicKey),
				config: NewVerifyConfig(),
				fields: *NewFields(),
			},
			want: &Verifier{
				key:             mldsa44.Public().(*mldsa.PublicKey),
				alg:             "",
				config:          NewVerifyConfig(),
				fields:          *NewFields(),
				foreignVerifier: nil,
			},
		},
		{
			name: "mldsa params mismatch",
			args: args{
				alg:    jwa.MLDSA65(),
				key:    mldsa44.Public().(*mldsa.PublicKey),
				config: NewVerifyConfig(),
				fields: *NewFields(),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "mldsa private key",
			args: args{
				alg:    jwa.MLDSA44(),
				key:    mldsa44,
				config: NewVerifyConfig(),
				fields: *NewFields(),
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewJWSVerifierWithAlg(nil, tt.args.alg, tt.args.key, tt.args.config, tt.args.fields)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewJWSVerifierWithAlg() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil {
				got.foreignVerifier = nil
			}
			if tt.want != nil {
				tt.want.foreignVerifier = nil
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewJWSVerifierWithAlg() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewJWSVerifierInfer(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	mldsa65, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	pub := mldsa65.Public().(*mldsa.PublicKey)
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	t.Run("ecdsa", func(t *testing.T) {
		v, err := NewJWSVerifier(nil, &p256.PublicKey, nil, *NewFields())
		require.NoError(t, err)
		require.NotNil(t, v.foreignVerifier)
	})
	t.Run("ecdsa p384", func(t *testing.T) {
		v, err := NewJWSVerifier(nil, &p384.PublicKey, nil, *NewFields())
		require.NoError(t, err)
		require.NotNil(t, v.foreignVerifier)
	})
	t.Run("ecdsa p521", func(t *testing.T) {
		v, err := NewJWSVerifier(nil, &p521.PublicKey, nil, *NewFields())
		require.NoError(t, err)
		require.NotNil(t, v.foreignVerifier)
	})
	t.Run("mldsa", func(t *testing.T) {
		v, err := NewJWSVerifier(nil, pub, nil, *NewFields())
		require.NoError(t, err)
		require.NotNil(t, v.foreignVerifier)
	})
	t.Run("ed25519 withalg", func(t *testing.T) {
		v, err := NewJWSVerifierWithAlg(nil, jwa.EdDSA(), edPub, nil, *NewFields())
		require.NoError(t, err)
		require.NotNil(t, v.foreignVerifier)
	})
	t.Run("rsa raw rejected", func(t *testing.T) {
		_, err := NewJWSVerifier(nil, &rsaPriv.PublicKey, nil, *NewFields())
		require.Error(t, err)
	})
	t.Run("allowlist deny", func(t *testing.T) {
		allowed, err := NewJWSAlgAllowlist(jwa.ES384())
		require.NoError(t, err)
		_, err = NewJWSVerifier(allowed, &p256.PublicKey, nil, *NewFields())
		require.Error(t, err)
	})
	t.Run("allowlist accept", func(t *testing.T) {
		allowed, err := NewJWSAlgAllowlist(jwa.ES256(), jwa.MLDSA65())
		require.NoError(t, err)
		v, err := NewJWSVerifier(allowed, &p256.PublicKey, nil, *NewFields())
		require.NoError(t, err)
		require.NotNil(t, v)
	})
}

func TestJWSAlgAllowlist(t *testing.T) {
	_, err := NewJWSAlgAllowlist()
	require.Error(t, err)
	_, err = NewJWSAlgAllowlist(jwa.NoSignature())
	require.Error(t, err)
	_, err = NewJWSAlgAllowlist(jwa.NewSignatureAlgorithm("NONE"))
	require.Error(t, err)
	_, err = NewJWSAlgAllowlist(jwa.NewSignatureAlgorithm("nope"))
	require.Error(t, err)
	a, err := NewJWSAlgAllowlist(jwa.NewSignatureAlgorithm("ES256"))
	require.NoError(t, err)
	require.True(t, a.Contains(jwa.ES256()))
	require.False(t, a.Contains(jwa.ES384()))
	var nilAllow *JWSAlgAllowlist
	require.False(t, nilAllow.Contains(jwa.ES256()))

	edModern, err := NewJWSAlgAllowlist(jwa.EdDSAEd25519())
	require.NoError(t, err)
	require.True(t, edModern.Contains(jwa.EdDSAEd25519()))
	require.True(t, edModern.Contains(jwa.EdDSA()), "legacy EdDSA aliases RFC 9864 Ed25519")
	edLegacy, err := NewJWSAlgAllowlist(jwa.EdDSA())
	require.NoError(t, err)
	require.True(t, edLegacy.Contains(jwa.EdDSAEd25519()))
}

func TestNewJWSSignerSignAlg(t *testing.T) {
	hmacKey := []byte(strings.Repeat("x", 32))
	t.Run("nil config defaults SignAlg false", func(t *testing.T) {
		s, err := NewJWSSigner(jwa.HS256(), hmacKey, nil, *NewFields())
		require.NoError(t, err)
		require.False(t, s.config.signAlg)
	})
	t.Run("SignAlg true rejected", func(t *testing.T) {
		_, err := NewJWSSigner(jwa.HS256(), hmacKey, NewSignConfig().SignAlg(true), *NewFields())
		require.Error(t, err)
	})
	t.Run("jwk key redirected", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		key, err := jwk.Import[jwk.Key](priv)
		require.NoError(t, err)
		_, err = NewJWSSigner(jwa.ES256(), key, nil, *NewFields())
		require.Error(t, err)
		require.Contains(t, err.Error(), "NewJWSSignerFromJWK")
	})
}

func TestNewJWSSignerFromJWK(t *testing.T) {
	fields := *NewFields().AddHeader("@method").AddHeader("date").AddHeader("content-type").AddQueryParam("pet")
	signCfg := NewSignConfig().SignAlg(false).setFakeCreated(1618884475).SetKeyID("jwk1")
	verifyCfg := NewVerifyConfig().SetVerifyCreated(false).SetKeyID("jwk1")

	t.Run("ecdsa p256 round trip", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		privJWK, err := jwk.Import[jwk.Key](priv)
		require.NoError(t, err)
		signer, err := NewJWSSignerFromJWK(privJWK, signCfg, fields)
		require.NoError(t, err)

		pubJWK, err := jwk.Import[jwk.Key](&priv.PublicKey)
		require.NoError(t, err)
		allowed, err := NewJWSAlgAllowlist(jwa.ES256())
		require.NoError(t, err)
		verifier, err := NewJWSVerifier(allowed, pubJWK, verifyCfg, fields)
		require.NoError(t, err)

		req := readRequest(httpreq2)
		sigInput, sig, err := SignRequest("sig1", *signer, req)
		require.NoError(t, err)
		req.Header.Add("Signature-Input", sigInput)
		req.Header.Add("Signature", sig)
		require.NoError(t, VerifyRequest("sig1", *verifier, req))
	})

	t.Run("ed25519 round trip", func(t *testing.T) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		privJWK, err := jwk.Import[jwk.Key](priv)
		require.NoError(t, err)
		require.NoError(t, privJWK.Set(jwk.AlgorithmKey, jwa.EdDSAEd25519()))
		signer, err := NewJWSSignerFromJWK(privJWK, signCfg, fields)
		require.NoError(t, err)

		pubJWK, err := jwk.Import[jwk.Key](pub)
		require.NoError(t, err)
		allowed, err := NewJWSAlgAllowlist(jwa.EdDSAEd25519())
		require.NoError(t, err)
		verifier, err := NewJWSVerifier(allowed, pubJWK, verifyCfg, fields)
		require.NoError(t, err)

		req := readRequest(httpreq2)
		sigInput, sig, err := SignRequest("sig1", *signer, req)
		require.NoError(t, err)
		req.Header.Add("Signature-Input", sigInput)
		req.Header.Add("Signature", sig)
		require.NoError(t, VerifyRequest("sig1", *verifier, req))
	})

	t.Run("mldsa44 round trip", func(t *testing.T) {
		priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
		require.NoError(t, err)
		privJWK, err := jwk.Import[jwk.Key](priv)
		require.NoError(t, err)
		require.NoError(t, privJWK.Set(jwk.AlgorithmKey, jwa.MLDSA44()))
		signer, err := NewJWSSignerFromJWK(privJWK, signCfg, fields)
		require.NoError(t, err)

		pub := priv.Public().(*mldsa.PublicKey)
		allowed, err := NewJWSAlgAllowlist(jwa.MLDSA44())
		require.NoError(t, err)
		verifier, err := NewJWSVerifier(allowed, pub, verifyCfg, fields)
		require.NoError(t, err)

		req := readRequest(httpreq2)
		sigInput, sig, err := SignRequest("sig1", *signer, req)
		require.NoError(t, err)
		req.Header.Add("Signature-Input", sigInput)
		req.Header.Add("Signature", sig)
		require.NoError(t, VerifyRequest("sig1", *verifier, req))
	})

	t.Run("hmac oct with alg", func(t *testing.T) {
		raw := []byte(strings.Repeat("k", 32))
		octJWK, err := jwk.Import[jwk.Key](raw)
		require.NoError(t, err)
		require.NoError(t, octJWK.Set(jwk.AlgorithmKey, jwa.HS256()))
		signer, err := NewJWSSignerFromJWK(octJWK, signCfg, fields)
		require.NoError(t, err)
		verifier, err := NewJWSVerifierWithAlg(nil, jwa.HS256(), raw, verifyCfg, fields)
		require.NoError(t, err)

		req := readRequest(httpreq2)
		sigInput, sig, err := SignRequest("sig1", *signer, req)
		require.NoError(t, err)
		req.Header.Add("Signature-Input", sigInput)
		req.Header.Add("Signature", sig)
		require.NoError(t, VerifyRequest("sig1", *verifier, req))
	})

	t.Run("public jwk rejected", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		pubJWK, err := jwk.Import[jwk.Key](&priv.PublicKey)
		require.NoError(t, err)
		_, err = NewJWSSignerFromJWK(pubJWK, nil, *NewFields())
		require.Error(t, err)
		require.Contains(t, err.Error(), "private")
	})

	t.Run("rsa without alg rejected", func(t *testing.T) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		rsaJWK, err := jwk.Import[jwk.Key](priv)
		require.NoError(t, err)
		_, err = NewJWSSignerFromJWK(rsaJWK, nil, *NewFields())
		require.Error(t, err)
	})

	t.Run("nil key", func(t *testing.T) {
		_, err := NewJWSSignerFromJWK(nil, nil, *NewFields())
		require.Error(t, err)
	})

	t.Run("SignAlg true rejected", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		privJWK, err := jwk.Import[jwk.Key](priv)
		require.NoError(t, err)
		_, err = NewJWSSignerFromJWK(privJWK, NewSignConfig().SignAlg(true), *NewFields())
		require.Error(t, err)
	})
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

func TestForeignSignerMLDSA(t *testing.T) {
	cases := []struct {
		name   string
		params mldsa.Parameters
		alg    jwa.SignatureAlgorithm
	}{
		{"MLDSA44", mldsa.MLDSA44(), jwa.MLDSA44()},
		{"MLDSA65", mldsa.MLDSA65(), jwa.MLDSA65()},
		{"MLDSA87", mldsa.MLDSA87(), jwa.MLDSA87()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := mldsa.GenerateKey(tc.params)
			require.NoError(t, err)
			pub := priv.Public().(*mldsa.PublicKey)

			config := NewSignConfig().setFakeCreated(1618884475).SignAlg(false)
			signatureName := "sig1"
			fields := *NewFields().AddHeader("@method").AddHeader("date").AddHeader("content-type").AddQueryParam("pet")
			signer, err := NewJWSSigner(tc.alg, priv, config.SetKeyID("pq1"), fields)
			require.NoError(t, err)

			req := readRequest(httpreq2)
			sigInput, sig, err := SignRequest(signatureName, *signer, req)
			require.NoError(t, err)
			req.Header.Add("Signature", sig)
			req.Header.Add("Signature-Input", sigInput)

			verifier, err := NewJWSVerifier(nil, pub, NewVerifyConfig().SetVerifyCreated(false).SetKeyID("pq1"), fields)
			require.NoError(t, err)
			require.NoError(t, VerifyRequest(signatureName, *verifier, req))
		})
	}
}

