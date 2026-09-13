package httpsign

import (
	"errors"
	"net/http"
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

	list, err = ResponseDetailsListByTag(res, "missing")
	require.NoError(t, err)
	assert.Empty(t, list)

	_, err = ResponseDetailsByTag(res, "missing")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSignatureTagNotFound))

	_, err = ResponseDetailsByTag(nil, "ctx1")
	require.Error(t, err)
	_, err = ResponseDetailsListByTag(nil, "ctx1")
	require.Error(t, err)

	t.Run("ambiguous", func(t *testing.T) {
		signerC, err := NewP256Signer(*priv, NewSignConfig().SetTag("ctx1").setFakeCreated(1660755826).SetKeyID("k1"), fields)
		require.NoError(t, err)
		inC, sigC, err := SignResponse("sig3", *signerC, res, nil)
		require.NoError(t, err)
		res.Header.Add("Signature-Input", inC)
		res.Header.Add("Signature", sigC)

		_, err = ResponseDetailsByTag(res, "ctx1")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrSignatureTagAmbiguous))

		list, err := ResponseDetailsListByTag(res, "ctx1")
		require.NoError(t, err)
		require.Len(t, list, 2)
		assert.ElementsMatch(t, []string{"sig1", "sig3"}, []string{list[0].Label, list[1].Label})
	})
}

func TestRequestDetailsByTagMixedAndCombined(t *testing.T) {
	priv, _, err := genP256KeyPair()
	require.NoError(t, err)
	fields := *NewFields().AddHeader("@method")

	t.Run("three distinct tags", func(t *testing.T) {
		req := readRequest(httpreq1)
		for _, tc := range []struct {
			label, tag string
		}{
			{"sig-a", "alpha"},
			{"sig-b", "beta"},
			{"sig-c", "gamma"},
		} {
			signer, err := NewP256Signer(*priv, NewSignConfig().SetTag(tc.tag).setFakeCreated(1618884475).SetKeyID("k1"), fields)
			require.NoError(t, err)
			in, sig, err := SignRequest(tc.label, *signer, req)
			require.NoError(t, err)
			req.Header.Add("Signature-Input", in)
			req.Header.Add("Signature", sig)
		}
		for _, tag := range []string{"alpha", "beta", "gamma"} {
			details, err := RequestDetailsByTag(req, tag)
			require.NoError(t, err)
			require.NotNil(t, details.Tag)
			assert.Equal(t, tag, *details.Tag)
		}
	})

	t.Run("untagged among tagged", func(t *testing.T) {
		req := readRequest(httpreq1)
		signerTagged, err := NewP256Signer(*priv, NewSignConfig().SetTag("app").setFakeCreated(1618884475).SetKeyID("k1"), fields)
		require.NoError(t, err)
		inT, sigT, err := SignRequest("sig-tagged", *signerTagged, req)
		require.NoError(t, err)
		req.Header.Add("Signature-Input", inT)
		req.Header.Add("Signature", sigT)

		signerPlain, err := NewP256Signer(*priv, NewSignConfig().setFakeCreated(1618884475).SetKeyID("k1"), fields)
		require.NoError(t, err)
		inP, sigP, err := SignRequest("sig-plain", *signerPlain, req)
		require.NoError(t, err)
		req.Header.Add("Signature-Input", inP)
		req.Header.Add("Signature", sigP)

		details, err := RequestDetailsByTag(req, "app")
		require.NoError(t, err)
		assert.Equal(t, "sig-tagged", details.Label)

		list, err := RequestDetailsListByTag(req, "app")
		require.NoError(t, err)
		require.Len(t, list, 1)

		all, err := signatureDetailsListFromHeaders(req.Header)
		require.NoError(t, err)
		require.Len(t, all, 2)
		var plain *MessageDetails
		for _, d := range all {
			if d.Label == "sig-plain" {
				plain = d
			}
		}
		require.NotNil(t, plain)
		assert.Nil(t, plain.Tag)
	})

	t.Run("single dictionary header line", func(t *testing.T) {
		req := readRequest(httpreq1)
		signerA, err := NewP256Signer(*priv, NewSignConfig().SetTag("app").setFakeCreated(1618884475).SetKeyID("k1"), fields)
		require.NoError(t, err)
		inA, sigA, err := SignRequest("sig-a", *signerA, req)
		require.NoError(t, err)
		signerB, err := NewP256Signer(*priv, NewSignConfig().SetTag("other").setFakeCreated(1618884475).SetKeyID("k1"), fields)
		require.NoError(t, err)
		inB, sigB, err := SignRequest("sig-b", *signerB, req)
		require.NoError(t, err)

		req.Header.Set("Signature-Input", inA+", "+inB)
		req.Header.Set("Signature", sigA+", "+sigB)

		details, err := RequestDetailsByTag(req, "other")
		require.NoError(t, err)
		assert.Equal(t, "sig-b", details.Label)
		list, err := RequestDetailsListByTag(req, "app")
		require.NoError(t, err)
		require.Len(t, list, 1)
		assert.Equal(t, "sig-a", list[0].Label)
	})

	t.Run("signature-input label missing from signature", func(t *testing.T) {
		req := readRequest(httpreq1)
		signer, err := NewP256Signer(*priv, NewSignConfig().SetTag("app").setFakeCreated(1618884475).SetKeyID("k1"), fields)
		require.NoError(t, err)
		in, sig, err := SignRequest("sig-a", *signer, req)
		require.NoError(t, err)
		req.Header.Set("Signature-Input", in)
		req.Header.Set("Signature", sig)

		signer2, err := NewP256Signer(*priv, NewSignConfig().SetTag("other").setFakeCreated(1618884475).SetKeyID("k1"), fields)
		require.NoError(t, err)
		in2, _, err := SignRequest("sig-b", *signer2, req)
		require.NoError(t, err)
		req.Header.Set("Signature-Input", in+", "+in2)
		// Signature still only has sig-a

		_, err = RequestDetailsByTag(req, "app")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing from Signature")

		_, err = RequestDetailsListByTag(req, "other")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing from Signature")
	})
}

func TestSignatureDetailsListFromHeadersEdges(t *testing.T) {
	t.Run("nil headers", func(t *testing.T) {
		list, err := signatureDetailsListFromHeaders(nil)
		require.NoError(t, err)
		assert.Nil(t, list)
	})

	t.Run("missing signature or signature-input", func(t *testing.T) {
		list, err := signatureDetailsListFromHeaders(http.Header{})
		require.NoError(t, err)
		assert.Nil(t, list)

		list, err = signatureDetailsListFromHeaders(http.Header{
			"Signature-Input": []string{`sig1=("@method");created=1`},
		})
		require.NoError(t, err)
		assert.Nil(t, list)

		list, err = signatureDetailsListFromHeaders(http.Header{
			"Signature": []string{`sig1=:YWJj:`},
		})
		require.NoError(t, err)
		assert.Nil(t, list)
	})

	t.Run("unparseable signature-input", func(t *testing.T) {
		_, err := signatureDetailsListFromHeaders(http.Header{
			"Signature-Input": []string{"not a dictionary"},
			"Signature":       []string{`sig1=:YWJj:`},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot parse Signature-Input")
	})
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
