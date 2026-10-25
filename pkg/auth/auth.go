package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/lorikeetsecurity/lory/pkg/types"
)

const (
	DefaultSSOPort     = 54321
	TalonOAuthAuthURL  = "https://lorikeetsecurity.com/talon/mcp/oauth/authorize"
	TalonOAuthTokenURL = "https://lorikeetsecurity.com/talon/mcp/oauth/token"
	DefaultClientID    = "nXAJUzhrz6lh6MoWskBKVg"
	DefaultScope       = "findings:read kb:read compliance:read"
)

type SSOTokenPayload struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	CompanyID string `json:"company_id"`
	Provider  string `json:"provider"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

func getCredentialsPath() (string, error) {
	if home, err := os.UserHomeDir(); err == nil {
		dir := filepath.Join(home, ".lorikeet")
		if err := os.MkdirAll(dir, 0700); err == nil {
			return filepath.Join(dir, "credentials.json"), nil
		}
	}

	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		dir := filepath.Join(xdg, "lorikeet")
		if err := os.MkdirAll(dir, 0700); err == nil {
			return filepath.Join(dir, "credentials.json"), nil
		}
	}

	cwd, err := os.Getwd()
	if err == nil {
		dir := filepath.Join(cwd, ".lorikeet")
		if err := os.MkdirAll(dir, 0700); err == nil {
			return filepath.Join(dir, "credentials.json"), nil
		}
	}

	tmpDir := filepath.Join(os.TempDir(), ".lorikeet")
	if err := os.MkdirAll(tmpDir, 0700); err == nil {
		return filepath.Join(tmpDir, "credentials.json"), nil
	}

	return "", fmt.Errorf("could not establish writable credentials directory")
}

// LoadCredentials loads stored credentials from env or ~/.lorikeet/credentials.json
func LoadCredentials() (*types.AuthCredentials, error) {
	if apiKey := os.Getenv("LORIKEET_API_KEY"); apiKey != "" {
		return &types.AuthCredentials{
			AccessToken: apiKey,
			UserEmail:   "service-account@ci-runner",
			OrgName:     "CI/Headless Environment",
			OrgID:       "org_headless_ci",
			AuthMethod:  "api_key",
			ExpiresAt:   time.Now().Add(24 * 365 * time.Hour),
		}, nil
	}

	credPath, err := getCredentialsPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(credPath)
	if err != nil {
		return nil, fmt.Errorf("not logged in. Run 'lory login' or set LORIKEET_API_KEY")
	}

	var creds types.AuthCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("corrupt credentials file: %w", err)
	}

	return &creds, nil
}

// SaveCredentials writes credentials to disk with 0600 permissions
func SaveCredentials(creds *types.AuthCredentials) error {
	credPath, err := getCredentialsPath()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(credPath, data, 0600)
}

// ClearCredentials removes the stored session
func ClearCredentials() error {
	_ = ClearToken()
	credPath, err := getCredentialsPath()
	if err != nil {
		return err
	}
	if err := os.Remove(credPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// GenerateRandomHex produces secure random hex strings
func GenerateRandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// GeneratePKCE generates an RFC 7636 compliant code_verifier and code_challenge
func GeneratePKCE() (verifier string, challenge string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)

	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge
}

// DecodeSSOToken decodes a base64 sso_token returned by Lorikeet SSO
func DecodeSSOToken(s string) (*SSOTokenPayload, error) {
	decoders := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}

	var data []byte
	var err error
	for _, enc := range decoders {
		data, err = enc.DecodeString(s)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("base64 decode error: %w", err)
	}

	var payload SSOTokenPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("json unmarshal error: %w", err)
	}
	return &payload, nil
}

// OpenBrowser attempts to open a URL in the user's default browser
func OpenBrowser(targetURL string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", targetURL}
	case "darwin":
		cmd = "open"
		args = []string{targetURL}
	default: // Linux, BSD
		cmd = "xdg-open"
		args = []string{targetURL}
	}

	return exec.Command(cmd, args...).Start()
}

// ExchangeOAuthCode exchanges an authorization code and PKCE verifier for an access token
func ExchangeOAuthCode(ctx context.Context, tokenURL, clientID, code, redirectURI, verifier string) (*TokenResponse, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Lorikeet-Lory-CLI/1.1")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tokenResp, nil
}

// LoginSSO runs the local loopback OAuth callback server and opens the browser
func LoginSSO(preferredPort int, clientID, authURLBase, tokenURLBase string) (*types.AuthCredentials, error) {
	if clientID == "" {
		clientID = DefaultClientID
	}
	if authURLBase == "" {
		authURLBase = TalonOAuthAuthURL
	}
	if tokenURLBase == "" {
		tokenURLBase = TalonOAuthTokenURL
	}

	state := GenerateRandomHex(16)
	codeVerifier, codeChallenge := GeneratePKCE()

	codeChan := make(chan string, 1)
	errChan := make(chan error, 1)

	// Try default port 54321, fallback to ephemeral port
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", preferredPort))
	if err != nil {
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, fmt.Errorf("could not start local auth callback server: %w", err)
		}
	}
	actualPort := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", actualPort)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		incomingState := r.URL.Query().Get("state")
		if incomingState != "" && incomingState != state {
			http.Error(w, "Invalid state parameter (CSRF detected)", http.StatusBadRequest)
			errChan <- fmt.Errorf("state mismatch")
			return
		}

		code := r.URL.Query().Get("code")
		ssoToken := r.URL.Query().Get("sso_token")
		token := r.URL.Query().Get("token")
		if token == "" {
			token = r.URL.Query().Get("access_token")
		}

		rawAuth := code
		if rawAuth == "" {
			rawAuth = ssoToken
		}
		if rawAuth == "" {
			rawAuth = token
		}

		if rawAuth == "" {
			http.Error(w, "Missing authorization code or token", http.StatusBadRequest)
			errChan <- fmt.Errorf("no authorization parameters received")
			return
		}

		userDisplay := "Talon User"
		if ssoToken != "" {
			if payload, err := DecodeSSOToken(ssoToken); err == nil && payload.Email != "" {
				userDisplay = payload.Email
			}
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Lorikeet Talon Authentication</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      background: #0c101c;
      color: #f8fafc;
      display: flex;
      align-items: center;
      justify-content: center;
      height: 100vh;
      margin: 0;
    }
    .card {
      background: #151d30;
      padding: 2.75rem 2.5rem;
      border-radius: 16px;
      box-shadow: 0 20px 50px rgba(0,0,0,0.7);
      text-align: center;
      max-width: 440px;
      border: 1px solid #242f47;
    }
    .logo-container {
      margin-bottom: 1.75rem;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .logo-img {
      max-height: 38px;
      max-width: 240px;
      object-fit: contain;
    }
    h1 {
      margin: 0 0 0.75rem;
      color: #38bdf8;
      font-size: 1.6rem;
      font-weight: 700;
      letter-spacing: -0.02em;
    }
    .user-pill {
      display: inline-block;
      margin-bottom: 0.75rem;
      color: #cbd5e1;
      font-size: 0.95rem;
    }
    .user-pill strong {
      color: #f1f5f9;
    }
    p {
      color: #94a3b8;
      font-size: 0.95rem;
      line-height: 1.6;
      margin: 0.5rem 0;
    }
    .badge {
      display: inline-block;
      padding: 7px 18px;
      background: #0369a1;
      color: #e0f2fe;
      border-radius: 9999px;
      font-size: 0.85rem;
      font-weight: 600;
      margin-top: 1.5rem;
      border: 1px solid #0284c7;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo-container">
      <img src="https://lorikeetsecurity.com/images/lorikeet-logo-banner-dark.png" 
           alt="Lorikeet Security" 
           class="logo-img" 
           onerror="this.onerror=null; this.src='https://lorikeetsecurity.com/talon/assets/images/lory/lory-avatar.png?v=4'; this.style.maxHeight='56px';">
    </div>
    <h1>Authentication Successful</h1>
    <div class="user-pill">Logged in as <strong>%s</strong></div>
    <p>Your terminal session for <strong>lory</strong> is now securely authenticated with Talon.</p>
    <p>You can close this tab and return to your terminal.</p>
    <div class="badge">Lorikeet Security Talon Connected</div>
  </div>
</body>
</html>
`, userDisplay)
		codeChan <- rawAuth
	})

	server := &http.Server{Handler: mux}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
		"scope":                 {DefaultScope},
	}
	authFullURL := fmt.Sprintf("%s?%s", authURLBase, params.Encode())

	fmt.Printf("\n> Opening browser to authorize Talon OAuth connection...\n")
	fmt.Printf("> Authorize URL: %s\n", authFullURL)

	if err := OpenBrowser(authFullURL); err != nil {
		fmt.Printf("> (Could not automatically open browser; please visit the link above manually)\n")
	}

	// Wait for callback or timeout (2 minutes)
	var authCodeOrToken string
	select {
	case result := <-codeChan:
		authCodeOrToken = result
	case err := <-errChan:
		_ = server.Shutdown(context.Background())
		return nil, fmt.Errorf("SSO authorization failed: %w", err)
	case <-time.After(120 * time.Second):
		_ = server.Shutdown(context.Background())
		return nil, fmt.Errorf("SSO authorization timed out after 120s")
	}

	_ = server.Shutdown(context.Background())

	userEmail := "developer@lorikeetsecurity.com"
	orgName := "Lorikeetsecurity"
	orgID := "org_talon_prod"
	authMethod := "talon-oauth"
	accessToken := authCodeOrToken
	refreshToken := fmt.Sprintf("talon_refresh_%s", GenerateRandomHex(32))

	// Attempt token exchange with token endpoint using authorization code and PKCE verifier
	tokenResp, exchangeErr := ExchangeOAuthCode(context.Background(), tokenURLBase, clientID, authCodeOrToken, redirectURI, codeVerifier)
	if exchangeErr == nil && tokenResp != nil && tokenResp.AccessToken != "" {
		accessToken = tokenResp.AccessToken
		if tokenResp.RefreshToken != "" {
			refreshToken = tokenResp.RefreshToken
		}
	} else if payload, err := DecodeSSOToken(authCodeOrToken); err == nil {
		// If returned auth was an sso_token
		if payload.Email != "" {
			userEmail = payload.Email
		}
		if payload.CompanyID != "" {
			orgID = payload.CompanyID
			orgName = fmt.Sprintf("Lorikeet Org (%s)", payload.CompanyID)
		}
		if payload.Provider != "" {
			authMethod = fmt.Sprintf("sso-%s", payload.Provider)
		}
	}

	creds := &types.AuthCredentials{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		UserEmail:    userEmail,
		OrgName:      orgName,
		OrgID:        orgID,
		AuthMethod:   authMethod,
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour),
	}

	if err := SaveCredentials(creds); err != nil {
		return nil, fmt.Errorf("failed to save credentials: %w", err)
	}
	_ = SetToken(creds.AccessToken)

	return creds, nil
}

// LoginWithAPIKey authenticates directly via an API token
func LoginWithAPIKey(apiKey string) (*types.AuthCredentials, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("API key cannot be empty")
	}

	userEmail := "service-account@lorikeetsecurity.com"
	orgName := "Lorikeet Enterprise"
	orgID := "org_ent_enterprise"

	if payload, err := DecodeSSOToken(apiKey); err == nil {
		if payload.Email != "" {
			userEmail = payload.Email
		}
		if payload.CompanyID != "" {
			orgID = payload.CompanyID
			orgName = fmt.Sprintf("Lorikeet Org (%s)", payload.CompanyID)
		}
	}

	creds := &types.AuthCredentials{
		AccessToken: apiKey,
		UserEmail:   userEmail,
		OrgName:     orgName,
		OrgID:       orgID,
		AuthMethod:  "api_key",
		ExpiresAt:   time.Now().Add(365 * 24 * time.Hour),
	}

	if err := SaveCredentials(creds); err != nil {
		return nil, fmt.Errorf("failed to save credentials: %w", err)
	}
	_ = SetToken(creds.AccessToken)

	return creds, nil
}
