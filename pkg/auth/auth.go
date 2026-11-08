package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
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

	"github.com/Lorikeet-Security/lory-cli/pkg/types"
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

const callbackHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Lorikeet Security — Authentication Successful</title>
  <style>
    :root {
      --primary: #ba5663;
      --primary-light: #db6574;
      --bg: #0a1628;
      --card: #142b49;
      --card-pill: #1a375d;
      --text: #ffffff;
      --text-muted: #94a3b8;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background: radial-gradient(ellipse at top, rgba(186, 86, 99, 0.12), transparent 60%), var(--bg);
      color: var(--text);
      padding: 24px;
    }
    .card {
      width: 100%;
      max-width: 440px;
      background: var(--card);
      border: 1px solid rgba(82, 82, 82, 0.6);
      border-radius: 14px;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.6);
      padding: 36px 32px 32px;
      text-align: center;
    }
    .brand-header {
      display: inline-flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 24px;
    }
    .brand-title {
      font-size: 1.15rem;
      font-weight: 800;
      letter-spacing: -0.01em;
      color: #ffffff;
    }
    .brand-subtitle {
      font-size: 0.72rem;
      font-weight: 700;
      letter-spacing: 0.12em;
      color: var(--primary-light);
      margin-left: 5px;
    }
    h1 {
      font-size: 1.45rem;
      font-weight: 700;
      margin: 0 0 14px;
      color: #ffffff;
      letter-spacing: -0.02em;
    }
    .user-pill {
      display: inline-block;
      background: var(--card-pill);
      border: 1px solid rgba(82, 82, 82, 0.4);
      border-radius: 9999px;
      padding: 8px 18px;
      font-size: 0.88rem;
      color: #cbd5e1;
      margin-bottom: 18px;
      word-break: break-all;
    }
    .user-pill strong {
      color: #ffffff;
      font-weight: 600;
    }
    p {
      margin: 0 0 8px;
      color: var(--text-muted);
      font-size: 0.92rem;
      line-height: 1.55;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      padding: 9px 22px;
      background: linear-gradient(135deg, var(--primary-light), var(--primary));
      color: #ffffff;
      border-radius: 9999px;
      font-size: 0.84rem;
      font-weight: 600;
      margin-top: 24px;
      border: 1px solid var(--primary-light);
      box-shadow: 0 4px 14px rgba(186, 86, 99, 0.4);
      letter-spacing: 0.02em;
    }
    .badge svg {
      width: 14px;
      height: 14px;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="brand-header">
      <svg width="34" height="34" viewBox="0 0 128 128" fill="none" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Lorikeet Security Logo">
        <defs>
          <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#db6574" />
            <stop offset="100%" stop-color="#ba5663" />
          </linearGradient>
          <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
            <feDropShadow dx="0" dy="2" stdDeviation="4" flood-color="#ba5663" flood-opacity="0.35"/>
          </filter>
        </defs>
        <path d="M64 8 L112 28 L112 60 C112 90 90 112 64 120 C38 112 16 90 16 60 L16 28 Z"
              fill="url(#shieldGrad)" stroke="#142b49" stroke-width="2" filter="url(#glow)"/>
        <path d="M64 18 L102 34 L102 58 C102 84 84 102 64 110 C44 102 26 84 26 58 L26 34 Z"
              fill="none" stroke="rgba(255,255,255,0.3)" stroke-width="1.5"/>
        <g transform="translate(64,62) scale(0.72)">
          <ellipse cx="0" cy="8" rx="18" ry="24" fill="#142b49"/>
          <circle cx="0" cy="-22" r="14" fill="#142b49"/>
          <path d="M14 -24 L28 -20 L14 -18 Z" fill="#ffffff" opacity="0.95"/>
          <circle cx="6" cy="-24" r="3" fill="#ffffff"/>
          <circle cx="7" cy="-24" r="1.5" fill="#142b49"/>
          <path d="M-6 -4 Q-30 4 -24 28 L-2 20 Z" fill="rgba(255,255,255,0.2)"/>
          <path d="M-8 28 L-14 44 L0 36 L14 44 L8 28" fill="#142b49"/>
        </g>
      </svg>
      <div>
        <span class="brand-title">Lorikeet</span>
        <span class="brand-subtitle">SECURITY</span>
      </div>
    </div>
    <h1>Authentication Successful</h1>
    <div class="user-pill">Logged in as <strong>{{USER_DISPLAY}}</strong></div>
    <p>Your terminal session for <strong>lory</strong> is now securely authenticated with Talon.</p>
    <p>You can safely close this browser window and return to your terminal.</p>
    <div class="badge">
      <svg viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M13.5 4.5L6.5 11.5L3 8" stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      Lorikeet Security Talon Connected
    </div>
  </div>
</body>
</html>`

func renderCallbackHTML(userDisplay string) string {
	return strings.Replace(callbackHTMLTemplate, "{{USER_DISPLAY}}", html.EscapeString(userDisplay), 1)
}

// FetchUserInfo queries platform userinfo / whoami endpoints
func FetchUserInfo(ctx context.Context, baseDomain, accessToken string) (*UserInfoResponse, error) {
	endpoints := []string{
		"/talon/mcp/oauth/userinfo",
		"/talon/api/whoami",
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
		req.Header.Set("User-Agent", "Lorikeet-Lory-CLI/1.2.1")

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
				if info.Email == "" && strings.Contains(info.Sub, "@") {
					info.Email = info.Sub
				}
				if info.Email == "" && strings.Contains(info.Subject, "@") {
					info.Email = info.Subject
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
	req.Header.Set("User-Agent", "Lorikeet-Lory-CLI/1.2.1")

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

type authCallbackResult struct {
	rawAuth     string
	tokenResp   *OAuthTokenResponse
	exchangeErr error
}

// LoginOAuth is an alias for LoginSSO providing interactive browser-based Talon OAuth 2.1 authentication
func LoginOAuth(preferredPort int, clientID, authURLBase, tokenURLBase string) (*types.AuthCredentials, error) {
	return LoginSSO(preferredPort, clientID, authURLBase, tokenURLBase)
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

	resultChan := make(chan authCallbackResult, 1)
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

		if errParam := r.URL.Query().Get("error"); errParam != "" {
			errDesc := r.URL.Query().Get("error_description")
			http.Error(w, fmt.Sprintf("Authorization error: %s (%s)", errParam, errDesc), http.StatusBadRequest)
			errChan <- fmt.Errorf("authorization denied: %s", errParam)
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

		var tokenResp *OAuthTokenResponse
		var exchangeErr error
		userDisplay := "Talon User"

		if ssoToken != "" {
			if payload, err := DecodeSSOToken(ssoToken); err == nil && payload.Email != "" {
				userDisplay = payload.Email
			}
		} else if code != "" {
			// Exchange authorization code immediately using PKCE verifier
			exchCtx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
			tokenResp, exchangeErr = ExchangeOAuthCode(exchCtx, tokenURLBase, clientID, code, redirectURI, codeVerifier)
			cancel()
			if exchangeErr == nil && tokenResp != nil {
				if tokenResp.UserEmail != "" {
					userDisplay = tokenResp.UserEmail
				} else if tokenResp.Email != "" {
					userDisplay = tokenResp.Email
				}
			}
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(renderCallbackHTML(userDisplay)))

		resultChan <- authCallbackResult{
			rawAuth:     rawAuth,
			tokenResp:   tokenResp,
			exchangeErr: exchangeErr,
		}
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
	var callbackRes authCallbackResult
	select {
	case res := <-resultChan:
		callbackRes = res
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
	accessToken := callbackRes.rawAuth
	refreshToken := fmt.Sprintf("talon_refresh_%s", GenerateRandomHex(32))

	tokenResp := callbackRes.tokenResp
	// If exchange wasn't completed in HTTP handler, attempt it now
	if tokenResp == nil && callbackRes.rawAuth != "" {
		if payload, err := DecodeSSOToken(callbackRes.rawAuth); err == nil {
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
		} else {
			// Exchange authorization code with token endpoint
			var err error
			tokenResp, err = ExchangeOAuthCode(context.Background(), tokenURLBase, clientID, callbackRes.rawAuth, redirectURI, codeVerifier)
			if err != nil {
				return nil, fmt.Errorf("OAuth token exchange failed: %w", err)
			}
		}
	} else if callbackRes.exchangeErr != nil {
		return nil, fmt.Errorf("OAuth token exchange failed: %w", callbackRes.exchangeErr)
	}

	// 1. Parse token response JSON for user_email, email, company_name, org_name, company_id
	if tokenResp != nil {
		accessToken = tokenResp.AccessToken
		if tokenResp.RefreshToken != "" {
			refreshToken = tokenResp.RefreshToken
		}

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
	}

	// 2. If email is empty, call FetchUserInfo against https://lorikeetsecurity.com/talon/mcp/oauth/userinfo with the Bearer token
	if userEmail == "" || orgName == "" {
		baseDomain := "https://lorikeetsecurity.com"
		if u, err := url.Parse(tokenURLBase); err == nil && u.Host != "" {
			baseDomain = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
		}
		if uinfo, err := FetchUserInfo(context.Background(), baseDomain, accessToken); err == nil && uinfo != nil {
			if userEmail == "" {
				if uinfo.Email != "" {
					userEmail = uinfo.Email
				} else if uinfo.UserEmail != "" {
					userEmail = uinfo.UserEmail
				}
			}
			if orgName == "" {
				if uinfo.CompanyName != "" {
					orgName = uinfo.CompanyName
				} else if uinfo.OrgName != "" {
					orgName = uinfo.OrgName
				}
			}
			if orgID == "" {
				if uinfo.CompanyID != "" {
					orgID = uinfo.CompanyID
				} else if uinfo.OrgID != "" {
					orgID = uinfo.OrgID
				}
			}
		}
	}

	// 3. If email is still empty, parse claims from access_token if it's a JWT
	if userEmail == "" || orgName == "" {
		if claims := parseJWTClaims(accessToken); claims != nil {
			if userEmail == "" {
				if em, ok := claims["email"].(string); ok && em != "" {
					userEmail = em
				} else if em, ok := claims["user_email"].(string); ok && em != "" {
					userEmail = em
				} else if sub, ok := claims["sub"].(string); ok && strings.Contains(sub, "@") {
					userEmail = sub
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

	// Also check token subject claim if it contains email
	if userEmail == "" && tokenResp != nil {
		if strings.Contains(tokenResp.Sub, "@") {
			userEmail = tokenResp.Sub
		} else if strings.Contains(tokenResp.Subject, "@") {
			userEmail = tokenResp.Subject
		}
	}

	// 4. If user identity still cannot be confirmed, FAIL with an explicit error instead of substituting fake developer credentials!
	if userEmail == "" {
		return nil, fmt.Errorf("could not confirm authenticated user identity from Talon OAuth session: email claim missing")
	}

	if orgName == "" {
		if orgID != "" {
			orgName = fmt.Sprintf("Lorikeet Org (%s)", orgID)
		} else {
			orgName = "Lorikeet Security"
		}
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
