package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestNewHMACSHA256Signer(t *testing.T) {
	type args struct {
		keyId string
		key   []byte
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
				keyId: "key1",
				key:   []byte(strings.Repeat("c", 64)),
			},
			want: &Signer{
				keyId: "key1",
				key:   []byte(strings.Repeat("c", 64)),
				alg:   "hmac-sha256",
			},
			wantErr: false,
		},
		{
			name: "key too short",
			args: args{
				keyId: "key2",
				key:   []byte("abc"),
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewHMACSHA256Signer(tt.args.keyId, tt.args.key)
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
		keyId string
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
				keyId: "key1",
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
				keyId: "key1",
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
				keyId: tt.fields.keyId,
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
