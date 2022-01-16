package httpsign

import (
	"reflect"
	"testing"
)

func TestConfig_SetSignCreated(t *testing.T) {
	type fields struct {
		signAlg     bool
		signCreated bool
		fakeCreated int64
	}
	type args struct {
		b bool
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *Config
	}{
		{
			name: "happy path",
			fields: fields{
				signAlg:     false,
				signCreated: false,
				fakeCreated: 8,
			},
			args: args{b: true},
			want: &Config{
				signAlg:     false,
				signCreated: true,
				fakeCreated: 8,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Config{
				signAlg:     tt.fields.signAlg,
				signCreated: tt.fields.signCreated,
				fakeCreated: tt.fields.fakeCreated,
			}
			if got := c.SignCreated(tt.args.b); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SignCreated() = %v, want %v", got, tt.want)
			}
		})
	}
}
