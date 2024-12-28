package auth

import (
	"net/http"
	"strings"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	const testPrefix = "ApiKey"
	const testToken = "1234"

	testHeader := http.Header{}
	testHeader.Set("Authorization", testPrefix+" "+testToken)

	token, err := GetAPIKey(testHeader)
	if err != nil {
		t.Fatalf("failed to get authorization token - error %v", err)
	}

	if token != testToken {
		t.Fatalf("token does not match test case - expected: %s actual: %s", token, testToken)
	}
}

func TestGetAPIKeyNoAuthHeader(t *testing.T) {
	testHeader := http.Header{}

	_, err := GetAPIKey(testHeader)
	if err != ErrNoAuthHeaderIncluded {
		t.Fatalf("expected '%s'", ErrNoAuthHeaderIncluded.Error())
	}
}

func TestGetAPIKeyMalformedHeader(t *testing.T) {
	const expectedErrorResp = "malformed authorization header"

	testHeader := http.Header{}
	testHeader.Set("Authorization", "WrongKey")

	_, err := GetAPIKey(testHeader)
	if err == nil {
		t.Fatalf("expected '%s'", expectedErrorResp)
	}
	if !strings.Contains(err.Error(), expectedErrorResp) {
		t.Fatalf("expected: '%s', actual: '%s'", expectedErrorResp, err.Error())
	}
}
