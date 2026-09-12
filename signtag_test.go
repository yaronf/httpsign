package httpsign

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestDetailsByTag(t *testing.T) {
	priv, _, err := genP256KeyPair()
	require.NoError(t, err)
	fields := *NewFields().AddHeader("@method")
	req := readRequest(httpreq1)

	signerA, err := NewP256Signer(*priv, NewSignConfig().SetTag("app").setFakeCreated(1618884475).SetKeyID("k1"), fields)
	require.NoError(t, err)
	inA, sigA, err := SignRequest("sig-a", *signerA, req)
	require.NoError(t, err)
	req.Header.Add("Signature-Input", inA)
	req.Header.Add("Signature", sigA)

	signerB, err := NewP256Signer(*priv, NewSignConfig().SetTag("other").setFakeCreated(1618884475).SetKeyID("k1"), fields)
	require.NoError(t, err)
	inB, sigB, err := SignRequest("sig-b", *signerB, req)
	require.NoError(t, err)
	req.Header.Add("Signature-Input", inB)
	req.Header.Add("Signature", sigB)

	t.Run("unique", func(t *testing.T) {
		details, err := RequestDetailsByTag(req, "app")
		require.NoError(t, err)
		assert.Equal(t, "sig-a", details.Label)
		require.NotNil(t, details.Tag)
		assert.Equal(t, "app", *details.Tag)
	})

	t.Run("list", func(t *testing.T) {
		list, err := RequestDetailsListByTag(req, "other")
		require.NoError(t, err)
		require.Len(t, list, 1)
		assert.Equal(t, "sig-b", list[0].Label)
		list, err = RequestDetailsListByTag(req, "missing")
		require.NoError(t, err)
		assert.Empty(t, list)
	})

	t.Run("not found", func(t *testing.T) {
		_, err := RequestDetailsByTag(req, "nope")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrSignatureTagNotFound))
	})

	t.Run("ambiguous", func(t *testing.T) {
		signerC, err := NewP256Signer(*priv, NewSignConfig().SetTag("app").setFakeCreated(1618884475).SetKeyID("k1"), fields)
		require.NoError(t, err)
		inC, sigC, err := SignRequest("sig-c", *signerC, req)
		require.NoError(t, err)
		req.Header.Add("Signature-Input", inC)
		req.Header.Add("Signature", sigC)

		_, err = RequestDetailsByTag(req, "app")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrSignatureTagAmbiguous))

		list, err := RequestDetailsListByTag(req, "app")
		require.NoError(t, err)
		require.Len(t, list, 2)
		labels := []string{list[0].Label, list[1].Label}
		assert.ElementsMatch(t, []string{"sig-a", "sig-c"}, labels)
	})

	t.Run("nil request", func(t *testing.T) {
		_, err := RequestDetailsByTag(nil, "app")
		require.Error(t, err)
		_, err = RequestDetailsListByTag(nil, "app")
		require.Error(t, err)
	})
}

func TestResponseDetailsByTag(t *testing.T) {
	priv, _, err := genP256KeyPair()
	require.NoError(t, err)
	fields := *NewFields().AddHeader("@status")
	res := readResponse(httpres2)

	signerA, err := NewP256Signer(*priv, NewSignConfig().SetTag("ctx1").setFakeCreated(1660755826).SetKeyID("k1"), fields)
	require.NoError(t, err)
	inA, sigA, err := SignResponse("sig1", *signerA, res, nil)
	require.NoError(t, err)
	res.Header.Add("Signature-Input", inA)
	res.Header.Add("Signature", sigA)

	signerB, err := NewP256Signer(*priv, NewSignConfig().SetTag("ctx2").setFakeCreated(1660755826).SetKeyID("k1"), fields)
	require.NoError(t, err)
	inB, sigB, err := SignResponse("sig2", *signerB, res, nil)
	require.NoError(t, err)
	res.Header.Add("Signature-Input", inB)
	res.Header.Add("Signature", sigB)

	details, err := ResponseDetailsByTag(res, "ctx2")
	require.NoError(t, err)
	assert.Equal(t, "sig2", details.Label)
	require.NotNil(t, details.Tag)
	assert.Equal(t, "ctx2", *details.Tag)

	list, err := ResponseDetailsListByTag(res, "ctx1")
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "sig1", list[0].Label)

	_, err = ResponseDetailsByTag(res, "missing")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSignatureTagNotFound))

	_, err = ResponseDetailsByTag(nil, "ctx1")
	require.Error(t, err)
	_, err = ResponseDetailsListByTag(nil, "ctx1")
	require.Error(t, err)
}

func TestRequestDetailsSetsLabel(t *testing.T) {
	priv, _, err := genP256KeyPair()
	require.NoError(t, err)
	fields := *NewFields().AddHeader("@method")
	req := readRequest(httpreq1)
	signer, err := NewP256Signer(*priv, NewSignConfig().SetTag("app").setFakeCreated(1618884475).SetKeyID("k1"), fields)
	require.NoError(t, err)
	in, sig, err := SignRequest("mysig", *signer, req)
	require.NoError(t, err)
	req.Header.Add("Signature-Input", in)
	req.Header.Add("Signature", sig)

	details, err := RequestDetails("mysig", req)
	require.NoError(t, err)
	assert.Equal(t, "mysig", details.Label)
}
