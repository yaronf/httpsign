package httpsign

import (
	"github.com/dunglas/httpsfv"
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
			fs:   HeaderList([]string{"hdr1", "hdr2", "@Hdr3"}),
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
			want:    `("hdr-name" "@query-params";name="qparamname")`,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.fs.asSignatureInput(tt.args.p)
			if (err != nil) != tt.wantErr {
				t.Errorf("asSignatureInput() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("asSignatureInput() got = %v, want %v", got, tt.want)
			}
		})
	}
}
