package httpsign

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func Test_sigComponentLen(t *testing.T) {
	type args struct {
		curve string
	}
	tests := []struct {
		name    string
		args    args
		want    int
		want1   int
		wantErr bool
	}{
		{
			name: "bad curve",
			args: args{
				curve: "P-77",
			},
			want:    0,
			want1:   0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := sigComponentLen(tt.args.curve)
			if (err != nil) != tt.wantErr {
				t.Errorf("sigComponentLen() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("sigComponentLen() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("sigComponentLen() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_ecdsaVerifyRaw(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Errorf("Failed to generate private key")
	}
	pubKey := privKey.Public().(*ecdsa.PublicKey)
	privKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Errorf("Failed to generate private key")
	}
	pubKey2 := privKey2.Public().(*ecdsa.PublicKey)
	type args struct {
		pub  *ecdsa.PublicKey
		hash []byte
		sig  []byte
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "nil pub",
			args: args{
				pub:  nil,
				hash: bytes.Repeat([]byte{88}, 1024),
				sig:  nil,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "bad curve",
			args: args{
				pub:  pubKey,
				hash: bytes.Repeat([]byte{88}, 1024),
				sig:  nil,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "bad sig",
			args: args{
				pub:  pubKey2,
				hash: bytes.Repeat([]byte{88}, 1024),
				sig:  nil,
			},
			want:    false,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ecdsaVerifyRaw(tt.args.pub, tt.args.hash, tt.args.sig)
			if (err != nil) != tt.wantErr {
				t.Errorf("ecdsaVerifyRaw() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ecdsaVerifyRaw() got = %v, want %v", got, tt.want)
			}
		})
	}
}
