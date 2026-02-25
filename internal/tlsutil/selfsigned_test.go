package tlsutil

import (
	"os"
	"testing"
)

func TestEnsureSelfSigned(t *testing.T) {
	dir := t.TempDir()
	cert, key, err := EnsureSelfSigned(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cert == "" || key == "" {
		t.Fatalf("empty cert/key paths: cert=%q key=%q", cert, key)
	}
	if _, err := os.Stat(cert); err != nil {
		t.Fatalf("cert not found: %v", err)
	}
	if _, err := os.Stat(key); err != nil {
		t.Fatalf("key not found: %v", err)
	}
}
