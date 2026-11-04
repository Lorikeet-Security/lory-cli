package main

import (
	"testing"

	"github.com/lorikeetsecurity/lory/apps/cli/cmd"
)

func TestMainShorthand_URLRecognition(t *testing.T) {
	urls := []string{
		"http://localhost:8080",
		"https://example.com",
		"https://api.lorikeetsecurity.com",
		"example.com",
		"127.0.0.1:3000",
	}

	for _, u := range urls {
		if !cmd.IsWebTarget(u) {
			t.Errorf("expected URL target %q to be recognized as web target for shorthand scan", u)
		}
	}

	nonUrls := []string{
		"./local/file.go",
		"path/to/file",
	}

	for _, p := range nonUrls {
		if cmd.IsWebTarget(p) {
			t.Errorf("expected path %q not to be recognized as web target", p)
		}
	}
}
