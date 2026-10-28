package auth_test

import (
	"encoding/json"
	"testing"

	"github.com/lorikeetsecurity/lory/pkg/auth"
)

func TestDecodeSSOToken(t *testing.T) {
	// Sample base64 token payload from Talon / loryaipentester SSO
	sampleToken := "eyJ1c2VyX2lkIjoiODlkZTc1NGExOWZhMjAxYzhjM2Q1M2YwNTgzMjhhN2Y4ZDNlZjU4ZDRmMjViMTQzYTRmMjg1ZWUzNjM2NmIxMjE3ZjU1Y2RjODRjZmZiMmU5NWE5YWYxZmEzNTJmZDhhM2RkIiwiZW1haWwiOiJyd2lsa2VAbG9yaWtlZXRzZWN1cml0eS5jb20iLCJjb21wYW55X2lkIjoiMjgxODAxNzQiLCJwcm92aWRlciI6Im1pY3Jvc29mdCJ9"

	payload, err := auth.DecodeSSOToken(sampleToken)
	if err != nil {
		t.Fatalf("failed to decode SSO token: %v", err)
	}

	if payload.Email != "rwilke@lorikeetsecurity.com" {
		t.Errorf("expected email rwilke@lorikeetsecurity.com, got %s", payload.Email)
	}

	if payload.CompanyID != "28180174" {
		t.Errorf("expected company_id 28180174, got %s", payload.CompanyID)
	}

	if payload.Provider != "microsoft" {
		t.Errorf("expected provider microsoft, got %s", payload.Provider)
	}
}

func TestGeneratePKCE(t *testing.T) {
	verifier, challenge := auth.GeneratePKCE()
	if len(verifier) < 43 {
		t.Errorf("expected verifier length >= 43, got %d", len(verifier))
	}
	if len(challenge) == 0 {
		t.Errorf("expected non-empty challenge")
	}
}

func TestOAuthTokenResponseParsing(t *testing.T) {
	jsonBlob := []byte(`{
		"access_token": "talon_token_12345",
		"token_type": "Bearer",
		"expires_in": 3600,
		"refresh_token": "talon_refresh_67890",
		"scope": "findings:read kb:read",
		"user_email": "alice@acme.corp",
		"company_name": "Acme Corp",
		"company_id": "org_acme_prod"
	}`)

	var resp auth.OAuthTokenResponse
	if err := json.Unmarshal(jsonBlob, &resp); err != nil {
		t.Fatalf("failed to unmarshal OAuthTokenResponse: %v", err)
	}

	if resp.AccessToken != "talon_token_12345" {
		t.Errorf("expected token talon_token_12345, got %s", resp.AccessToken)
	}
	if resp.UserEmail != "alice@acme.corp" {
		t.Errorf("expected user_email alice@acme.corp, got %s", resp.UserEmail)
	}
	if resp.CompanyName != "Acme Corp" {
		t.Errorf("expected company_name Acme Corp, got %s", resp.CompanyName)
	}
	if resp.CompanyID != "org_acme_prod" {
		t.Errorf("expected company_id org_acme_prod, got %s", resp.CompanyID)
	}
}
