package httpsign

import (
	"bytes"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyRequestRejectsMalformedComponentParams(t *testing.T) {
	key := bytes.Repeat([]byte("k"), 64)
	verifier, err := NewHMACSHA256Verifier(key, nil, Headers("@method"))
	require.NoError(t, err)

	now := time.Now().Unix()
	vectors := []struct {
		name   string
		sigIn  string
		errSub string
	}{
		{
			name:  "non-bool req",
			sigIn: fmt.Sprintf(`sig1=("@method" "x";req=1);created=%d`, now),
		},
		{
			name:  "non-bool sf",
			sigIn: fmt.Sprintf(`sig1=("@method" "host";sf="y");created=%d`, now),
		},
		{
			name:  "non-bool bs",
			sigIn: fmt.Sprintf(`sig1=("@method" "host";bs=0);created=%d`, now),
		},
		{
			name:  "non-bool tr",
			sigIn: fmt.Sprintf(`sig1=("@method" "host";tr=*x*);created=%d`, now),
		},
		{
			name:  "non-bool optional",
			sigIn: fmt.Sprintf(`sig1=("@method" "host";optional=1);created=%d`, now),
			errSub: "unknown component parameter",
		},
		{
			name:  "bool optional param not in RFC",
			sigIn: fmt.Sprintf(`sig1=("@method" "host";optional);created=%d`, now),
			errSub: "unknown component parameter",
		},
		{
			name:   "non-string key",
			sigIn:  fmt.Sprintf(`sig1=("@method" "cookie";key=1);created=%d`, now),
			errSub: `malformed "key" parameter`,
		},
		{
			name:   "non-string name",
			sigIn:  fmt.Sprintf(`sig1=("@method" "@query-param";name=1);created=%d`, now),
			errSub: `malformed "name" parameter`,
		},
		{
			name:   "unknown foo param",
			sigIn:  fmt.Sprintf(`sig1=("@method" "host";foo=1);created=%d`, now),
			errSub: `unknown component parameter "foo"`,
		},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "http://example.com/", nil)
			require.NoError(t, err)
			req.Header.Set("Host", "example.com")
			req.Header.Set("Signature-Input", v.sigIn)
			req.Header.Set("Signature", "sig1=:QUFBQQ==:")

			errSub := v.errSub
			if errSub == "" {
				errSub = "malformed"
			}

			require.NotPanics(t, func() {
				err := VerifyRequest("sig1", *verifier, req)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), errSub)
			})
		})
	}
}

func TestVerifyResponseRejectsMalformedComponentParams(t *testing.T) {
	key := bytes.Repeat([]byte("k"), 64)
	verifier, err := NewHMACSHA256Verifier(key, nil, Headers("@status"))
	require.NoError(t, err)

	now := time.Now().Unix()
	sigIn := fmt.Sprintf(`sig1=("@status" "host";req=1);created=%d`, now)

	res := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Signature-Input": []string{sigIn},
			"Signature":       []string{"sig1=:QUFBQQ==:"},
		},
	}

	require.NotPanics(t, func() {
		err := VerifyResponse("sig1", *verifier, res, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "malformed")
	})
}

func TestHasTrailerFieldsRejectsMalformedTrParam(t *testing.T) {
	sigs, err := parseSignatureInput(
		fmt.Sprintf(`("@method" "host";tr=0);created=%d`, time.Now().Unix()),
		"sig1",
	)
	require.NoError(t, err)

	_, err = sigs.fields.hasTrailerFields(false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), `malformed "tr" parameter`)
}

func TestApplyVerificationFieldConstraintsRejectsMalformedParams(t *testing.T) {
	sigs, err := parseSignatureInput(`("@method" "host";sf="y")`, "sig1")
	require.NoError(t, err)

	err = applyVerificationFieldConstraints(sigs.fields)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), `malformed "sf" parameter`)
}

func TestApplyVerificationFieldConstraintsRejectsOptionalParam(t *testing.T) {
	sigs, err := parseSignatureInput(`("@method";optional)`, "sig1")
	require.NoError(t, err)

	err = applyVerificationFieldConstraints(sigs.fields)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), `unknown component parameter "optional"`)
}

func TestApplyVerificationFieldConstraintsRejectsMalformedStringParams(t *testing.T) {
	vectors := []struct {
		name    string
		sigIn   string
		errSub  string
	}{
		{
			name:   "non-string key",
			sigIn:  `("@method" "cookie";key=1)`,
			errSub: `malformed "key" parameter`,
		},
		{
			name:   "non-string name",
			sigIn:  `("@method" "@query-param";name=1)`,
			errSub: `malformed "name" parameter`,
		},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			sigs, err := parseSignatureInput(v.sigIn, "sig1")
			require.NoError(t, err)

			err = applyVerificationFieldConstraints(sigs.fields)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), v.errSub)
		})
	}
}

func TestApplyVerificationFieldConstraintsRejectsUnknownParam(t *testing.T) {
	sigs, err := parseSignatureInput(`("@method" "host";foo=1)`, "sig1")
	require.NoError(t, err)

	err = applyVerificationFieldConstraints(sigs.fields)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), `unknown component parameter "foo"`)
}

func TestApplyFieldConstraintsSetCookieRequiresBinarySequence(t *testing.T) {
	err := applyFieldConstraints(Headers("set-cookie"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "binary sequence")
}

func TestApplyFieldConstraintsSetCookieWithBinarySequence(t *testing.T) {
	fields := *NewFields().AddHeaderExt("set-cookie", false, true, false, false)
	err := applyFieldConstraints(fields)
	assert.NoError(t, err)
}

func TestApplyFieldConstraintsAllowsOptionalMarkerOnSignPath(t *testing.T) {
	fields := *NewFields().AddHeaderOptional("cache-control")
	err := applyFieldConstraints(fields)
	assert.NoError(t, err)
}
