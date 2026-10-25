package auth

import (
	"os"
	"path/filepath"
	"strings"
)

func getTokenFilePath() (string, error) {
	candidates := make([]string, 0)
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".lorikeet"))
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		candidates = append(candidates, filepath.Join(xdg, "lorikeet"))
	}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, ".lorikeet"))
	}
	candidates = append(candidates, filepath.Join(os.TempDir(), ".lorikeet"))

	for _, dir := range candidates {
		if err := os.MkdirAll(dir, 0700); err == nil {
			return filepath.Join(dir, "token"), nil
		}
	}
	return filepath.Join(os.TempDir(), "lory_token"), nil
}

// GetToken returns the active Lorikeet/Lory token
func GetToken() string {
	if token := os.Getenv("LORIKEET_TOKEN"); token != "" {
		return token
	}
	if token := os.Getenv("LORY_TOKEN"); token != "" {
		return token
	}
	if token := os.Getenv("LORIKEET_API_KEY"); token != "" {
		return token
	}

	path, err := getTokenFilePath()
	if err == nil {
		if data, err := os.ReadFile(path); err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return ""
}

// SetToken saves the user's access token
func SetToken(token string) error {
	path, err := getTokenFilePath()
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.TrimSpace(token)), 0600)
}

// ClearToken removes the stored token
func ClearToken() error {
	path, err := getTokenFilePath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
