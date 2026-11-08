package client

import "testing"

func TestUserAgent(t *testing.T) {
	expected := "Lorikeet-Lory-CLI/1.2.2"
	if UserAgent != expected {
		t.Errorf("expected UserAgent %q, got %q", expected, UserAgent)
	}
}
