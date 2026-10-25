package auth_test

import (
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
