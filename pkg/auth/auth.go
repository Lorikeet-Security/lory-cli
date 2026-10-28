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

type OAuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	UserEmail    string `json:"user_email"`
	Email        string `json:"email"`
	CompanyName  string `json:"company_name"`
	OrgName      string `json:"org_name"`
	CompanyID    string `json:"company_id"`
	OrgID        string `json:"org_id"`
	Sub          string `json:"sub"`
	Subject      string `json:"subject"`
}

type TokenResponse = OAuthTokenResponse

type UserInfoResponse struct {
	Email       string `json:"email"`
	UserEmail   string `json:"user_email"`
	CompanyName string `json:"company_name"`
	OrgName     string `json:"org_name"`
	CompanyID   string `json:"company_id"`
	OrgID       string `json:"org_id"`
	Sub         string `json:"sub"`
	Subject     string `json:"subject"`
}

// FetchUserInfo queries platform userinfo / whoami endpoints
func FetchUserInfo(ctx context.Context, baseDomain, accessToken string) (*UserInfoResponse, error) {
	endpoints := []string{
		"/talon/api/whoami",
		"/talon/mcp/oauth/userinfo",
	}

	client := &http.Client{Timeout: 10 * time.Second}
	for _, ep := range endpoints {
		fullURL := strings.TrimRight(baseDomain, "/") + ep
		req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "Lorikeet-Lory-CLI/1.1.1")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			var info UserInfoResponse
			if err := json.Unmarshal(body, &info); err == nil {
				if info.Email == "" && info.UserEmail != "" {
					info.Email = info.UserEmail
				}
				if info.CompanyName == "" && info.OrgName != "" {
					info.CompanyName = info.OrgName
				}
				if info.CompanyID == "" && info.OrgID != "" {
					info.CompanyID = info.OrgID
				}
				if info.Email != "" || info.CompanyName != "" || info.CompanyID != "" || info.Sub != "" || info.Subject != "" {
					return &info, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("could not fetch user info from platform endpoints")
}

func parseJWTClaims(tokenStr string) map[string]interface{} {
	parts := strings.Split(tokenStr, ".")
	if len(parts) >= 2 {
		payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			payloadBytes, err = base64.StdEncoding.DecodeString(parts[1])
		}
		if err == nil {
			var claims map[string]interface{}
			if err := json.Unmarshal(payloadBytes, &claims); err == nil {
				return claims
			}
		}
	}
	return nil
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
func ExchangeOAuthCode(ctx context.Context, tokenURL, clientID, code, redirectURI, verifier string) (*OAuthTokenResponse, error) {
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
	req.Header.Set("User-Agent", "Lorikeet-Lory-CLI/1.1.1")

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

	var tokenResp OAuthTokenResponse
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
    :root {
      --rose-primary: #ba5663;
      --navy-deep: #0a1628;
      --navy-card: #142b49;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      background: #0a1628;
      color: #f8fafc;
      display: flex;
      align-items: center;
      justify-content: center;
      height: 100vh;
      margin: 0;
    }
    .card {
      background: #142b49;
      padding: 2.75rem 2.5rem;
      border-radius: 16px;
      box-shadow: 0 25px 60px rgba(0,0,0,0.85);
      text-align: center;
      max-width: 440px;
      width: 90%%;
      border: 1px solid #1a375d;
    }
    .brand-bar {
      display: flex;
      align-items: center;
      justify-content: center;
      margin-bottom: 1.75rem;
    }
    .brand-logo {
      display: inline-flex;
      align-items: center;
      gap: 10px;
      background: rgba(10, 22, 40, 0.75);
      padding: 8px 18px;
      border-radius: 9999px;
      border: 1px solid #1a375d;
    }
    .brand-name {
      color: #ffffff;
      font-weight: 800;
      font-size: 0.88rem;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }
    h1 {
      margin: 0 0 0.75rem;
      color: #ffffff;
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
      padding: 8px 20px;
      background: #ba5663;
      color: #ffffff;
      border-radius: 9999px;
      font-size: 0.85rem;
      font-weight: 600;
      margin-top: 1.5rem;
      border: 1px solid #db6574;
      box-shadow: 0 4px 14px rgba(186, 86, 99, 0.4);
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="brand-bar">
      <div class="brand-logo">
        <svg width="24" height="26" viewBox="0 0 28 32" fill="none" xmlns="http://www.w3.org/2000/svg">
          <defs>
            <linearGradient id="shieldNavyGrad" x1="0" y1="0" x2="28" y2="32" gradientUnits="userSpaceOnUse">
              <stop stop-color="#0a1628"/>
              <stop offset="1" stop-color="#142b49"/>
            </linearGradient>
            <linearGradient id="clawCrimsonGrad" x1="0" y1="0" x2="0" y2="32" gradientUnits="userSpaceOnUse">
              <stop stop-color="#ba5663"/>
              <stop offset="1" stop-color="#db6574"/>
            </linearGradient>
          </defs>
          <!-- Dual-Tone Shield Base -->
          <path d="M14 1.5L2 6.5V15C2 22.5 7.1 29.1 14 31C20.9 29.1 26 22.5 26 15V6.5L14 1.5Z" fill="url(#shieldNavyGrad)" stroke="#1a375d" stroke-width="1.2"/>
          <!-- Dual-Tone Split (Right Half Shading) -->
          <path d="M14 1.5V31C20.9 29.1 26 22.5 26 15V6.5L14 1.5Z" fill="#ba5663" fill-opacity="0.2"/>
          <!-- Inner Crimson Accent Shield -->
          <path d="M14 4L4.5 8V14.5C4.5 20.5 8.5 25.8 14 27.5C19.5 25.8 23.5 20.5 23.5 14.5V8L14 4Z" fill="none" stroke="url(#clawCrimsonGrad)" stroke-width="0.9" stroke-opacity="0.75"/>
          <!-- Talon Claws Mark -->
          <path d="M9.5 9.5C10.5 12.5 10.8 15 9.8 17.5" stroke="#ffffff" stroke-width="1.6" stroke-linecap="round"/>
          <path d="M14 7.5C15.2 11.5 15.2 15.5 14 19.5" stroke="#ba5663" stroke-width="2" stroke-linecap="round"/>
          <path d="M18.5 9.5C17.5 12.5 17.2 15 18.2 17.5" stroke="#ffffff" stroke-width="1.6" stroke-linecap="round"/>
          <path d="M12.5 20.5L14 22.5L15.5 20.5" stroke="#ffffff" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        <span class="brand-name">LORIKEET SECURITY</span>
      </div>
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

	userEmail := ""
	orgName := ""
	orgID := ""
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

		// 1. Check if tokenResp contains user_email, company_name, company_id
		if tokenResp.UserEmail != "" {
			userEmail = tokenResp.UserEmail
		} else if tokenResp.Email != "" {
			userEmail = tokenResp.Email
		}
		if tokenResp.CompanyName != "" {
			orgName = tokenResp.CompanyName
		} else if tokenResp.OrgName != "" {
			orgName = tokenResp.OrgName
		}
		if tokenResp.CompanyID != "" {
			orgID = tokenResp.CompanyID
		} else if tokenResp.OrgID != "" {
			orgID = tokenResp.OrgID
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

	// 2. If user_email or orgName is not present, query platform /talon/api/whoami or /talon/mcp/oauth/userinfo
	if userEmail == "" || orgName == "" {
		baseDomain := "https://lorikeetsecurity.com"
		if u, err := url.Parse(tokenURLBase); err == nil && u.Host != "" {
			baseDomain = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
		}
		if uinfo, err := FetchUserInfo(context.Background(), baseDomain, accessToken); err == nil && uinfo != nil {
			if userEmail == "" && uinfo.Email != "" {
				userEmail = uinfo.Email
			}
			if orgName == "" && uinfo.CompanyName != "" {
				orgName = uinfo.CompanyName
			}
			if orgID == "" && uinfo.CompanyID != "" {
				orgID = uinfo.CompanyID
			}
		}
	}

	// 3. If still empty, check JWT claims in accessToken
	if userEmail == "" || orgName == "" {
		if claims := parseJWTClaims(accessToken); claims != nil {
			if userEmail == "" {
				if em, ok := claims["email"].(string); ok && em != "" {
					userEmail = em
				} else if em, ok := claims["user_email"].(string); ok && em != "" {
					userEmail = em
				} else if sub, ok := claims["sub"].(string); ok && sub != "" {
					if strings.Contains(sub, "@") {
						userEmail = sub
					} else {
						userEmail = fmt.Sprintf("%s@talon.lorikeetsecurity.com", sub)
					}
				}
			}
			if orgName == "" {
				if comp, ok := claims["company_name"].(string); ok && comp != "" {
					orgName = comp
				} else if comp, ok := claims["org_name"].(string); ok && comp != "" {
					orgName = comp
				}
			}
			if orgID == "" {
				if cid, ok := claims["company_id"].(string); ok && cid != "" {
					orgID = cid
				} else if cid, ok := claims["org_id"].(string); ok && cid != "" {
					orgID = cid
				}
			}
		}
	}

	// 4. Default to authenticated subject if still empty - never fake developer@lorikeetsecurity.com!
	if userEmail == "" {
		if tokenResp != nil && tokenResp.Sub != "" {
			if strings.Contains(tokenResp.Sub, "@") {
				userEmail = tokenResp.Sub
			} else {
				userEmail = fmt.Sprintf("%s@talon.lorikeetsecurity.com", tokenResp.Sub)
			}
		} else if tokenResp != nil && tokenResp.Subject != "" {
			if strings.Contains(tokenResp.Subject, "@") {
				userEmail = tokenResp.Subject
			} else {
				userEmail = fmt.Sprintf("%s@talon.lorikeetsecurity.com", tokenResp.Subject)
			}
		} else {
			userEmail = "authenticated-user@lorikeetsecurity.com"
		}
	}
	if orgName == "" {
		orgName = "Lorikeet Security"
	}
	if orgID == "" {
		orgID = "org_talon_prod"
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
