package httpsign

import (
	"github.com/dunglas/httpsfv"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFields_asSignatureInput(t *testing.T) {
	type args struct {
		p *httpsfv.Params
	}
	tests := []struct {
		name    string
		fs      Fields
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Just headers",
			fs:   Headers("hdr1", "hdr2", "@Hdr3"),
			args: args{
				p: httpsfv.NewParams(),
			},
			want:    `("hdr1" "hdr2" "@hdr3")`,
			wantErr: false,
		},
		{
			name: "Misc components",
			fs: func() Fields {
				f := NewFields()
				f.AddHeader("hdr-Name")
				f.AddQueryParam("qparamname")
				return *f
			}(),
			args: args{
				p: httpsfv.NewParams(),
			},
			want:    `("hdr-name" "@query-param";name="qparamname")`,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.fs.asSignatureInput(tt.args.p)
			if (err != nil) != tt.wantErr {
				t.Errorf("asSignatureBase() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("asSignatureBase() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_field_String(t *testing.T) {
	tests := []struct {
		name string
		f    field
		want string
	}{
		{
			name: "field to string",
			f:    *fromQueryParam("qp1"),
			want: "\"@query-param\";name=\"qp1\"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, tt.f.String(), "String()")
		})
	}
}
