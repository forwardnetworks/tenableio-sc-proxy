package auth

import "testing"

func TestParseXAPIKey(t *testing.T) {
	h := "accesskey=abc123; secretkey=xyz789;"
	creds, err := ParseXAPIKey(h)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds.AccessKey != "abc123" || creds.SecretKey != "xyz789" {
		t.Fatalf("unexpected creds: %#v", creds)
	}
}

func TestParseXAPIKeyMissing(t *testing.T) {
	_, err := ParseXAPIKey("accesskey=abc123;")
	if err == nil {
		t.Fatal("expected error")
	}
}
