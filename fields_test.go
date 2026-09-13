package httpsign

import (
	"testing"

	"github.com/dunglas/httpsfv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestFields_hasHeader(t *testing.T) {
	tests := []struct {
		name   string
		fields *Fields
		header string
		want   bool
	}{
		{
			name:   "bare header via AddHeaders",
			fields: NewFields().AddHeaders("content-digest"),
			header: "content-digest",
			want:   true,
		},
		{
			name:   "optional header via AddHeaderOptional",
			fields: NewFields().AddHeaderOptional("content-digest"),
			header: "content-digest",
			want:   true,
		},
		{
			name:   "header with params via AddHeaderExt",
			fields: NewFields().AddHeaderExt("content-digest", true, false, false, false),
			header: "Content-Digest",
			want:   true,
		},
		{
			name:   "associated-request component via AddRequestComponent",
			fields: NewFields().AddRequestComponent("@method"),
			header: "@method",
			want:   true,
		},
		{
			name:   "header not in fields",
			fields: NewFields().AddHeaders("content-type"),
			header: "content-digest",
			want:   false,
		},
		{
			name:   "query param not a header",
			fields: NewFields().AddQueryParam("foo"),
			header: "content-digest",
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.fields.hasHeader(tt.header)
			assert.Equalf(t, tt.want, got, "hasHeader(%q)", tt.header)
		})
	}
}

func TestAddRequestComponent(t *testing.T) {
	got := NewFields().AddRequestComponent("@method").AddRequestComponent("@path")
	want := NewFields().
		AddHeaderExt("@method", false, false, true, false).
		AddHeaderExt("@path", false, false, true, false)
	require.Equal(t, len(want.f), len(got.f))
	for i := range got.f {
		assert.True(t, got.f[i].Equal(want.f[i]), "field %d: got %s want %s", i, got.f[i], want.f[i])
		req, err := got.f[i].associatedRequest()
		require.NoError(t, err)
		assert.True(t, req)
		opt, err := got.f[i].optional()
		require.NoError(t, err)
		assert.False(t, opt)
	}
	assert.Equal(t, `"@method";req`, got.f[0].String())
	assert.Equal(t, `"@path";req`, got.f[1].String())
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
