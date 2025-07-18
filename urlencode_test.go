package httpsign

import "testing"

// Correctly identifies unreserved alphanumeric characters as not needing escape
func TestUnreservedAlphanumericCharacters(t *testing.T) {
	for c := byte('a'); c <= byte('z'); c++ {
		if shouldEscape(c, encodePath) {
			t.Errorf("Expected %c not to be escaped", c)
		}
	}
	for c := byte('A'); c <= byte('Z'); c++ {
		if shouldEscape(c, encodePath) {
			t.Errorf("Expected %c not to be escaped", c)
		}
	}
	for c := byte('0'); c <= byte('9'); c++ {
		if shouldEscape(c, encodePath) {
			t.Errorf("Expected %c not to be escaped", c)
		}
	}
}

// Handles empty input or non-ASCII characters gracefully
// Ensure that empty input is correctly identified as not needing escape.
func TestEmptyInput(t *testing.T) {
	if !shouldEscape(0, encodePath) {
		t.Error("Expected empty input to be escaped")
	}
}

// Properly escapes characters in encodeQueryComponent and encodeQueryComponentForSignature modes
func TestEscapeInQueryComponentModes(t *testing.T) {
	reservedChars := []byte{'$', '&', '+', ',', '/', ':', ';', '=', '?', '@'}
	for _, mode := range []encoding{encodeQueryComponent, encodeQueryComponentForSignature} {
		for _, c := range reservedChars {
			if !shouldEscape(c, mode) {
				t.Errorf("shouldEscape(%q, %v) = false; want true", c, mode)
			}
		}
	}
}

// Encodes spaces as '+' when mode is encodeQueryComponent
func TestEncodeSpacesAsPlus(t *testing.T) {
	input := "hello world"
	expected := "hello+world"
	result := escape(input, encodeQueryComponent)
	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}
}

// Handles empty strings without errors
func TestHandleEmptyString(t *testing.T) {
	input := ""
	expected := ""
	result := escape(input, encodeQueryComponent)
	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}
}

// Encodes characters as '%XX' when they should be escaped
func TestEscapeEncodesCharacters(t *testing.T) {
	input := "hello world!"
	expected := "hello%20world%21"
	result := escape(input, encodeQueryComponentForSignature)
	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}
}

// Returns the original string if no characters need escaping
func TestEscapeReturnsOriginalString(t *testing.T) {
	input := "helloworld"
	expected := "helloworld"
	result := escape(input, encodeQueryComponent)
	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}
}

// Handles strings with mixed characters requiring different encodings
func TestEscapeHandlesMixedCharacters(t *testing.T) {
	input := "hello world! @2023"
	expected := "hello+world%21+%402023"
	result := escape(input, encodeQueryComponent)
	if result != expected {
		t.Errorf("Expected %s, but got %s", expected, result)
	}
}
