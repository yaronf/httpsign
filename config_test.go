package httpsign

import (
	"reflect"
	"testing"
)

func TestConfig_String(t *testing.T) {
	type fields struct {
		SignAlg     bool
		SignCreated bool
		FakeCreated int64
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "happy path",
			fields: fields{
				SignAlg:     true,
				SignCreated: true,
				FakeCreated: 7,
			},
			want: `{
    "SignAlg": true,
    "SignCreated": true,
    "FakeCreated": 7
}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Config{
				SignAlg:     tt.fields.SignAlg,
				SignCreated: tt.fields.SignCreated,
				FakeCreated: tt.fields.FakeCreated,
			}
			if got := c.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_SetSignCreated(t *testing.T) {
	type fields struct {
		SignAlg     bool
		SignCreated bool
		FakeCreated int64
	}
	type args struct {
		b bool
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   Config
	}{
		{
			name: "happy path",
			fields: fields{
				SignAlg:     false,
				SignCreated: false,
				FakeCreated: 8,
			},
			args: args{b: true},
			want: Config{
				SignAlg:     false,
				SignCreated: true,
				FakeCreated: 8,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Config{
				SignAlg:     tt.fields.SignAlg,
				SignCreated: tt.fields.SignCreated,
				FakeCreated: tt.fields.FakeCreated,
			}
			if got := c.SetSignCreated(tt.args.b); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SetSignCreated() = %v, want %v", got, tt.want)
			}
		})
	}
}
