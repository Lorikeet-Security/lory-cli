package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lorikeetsecurity/lory/pkg/types"
)

const (
	DefaultBaseURL   = "https://lorikeetsecurity.com"
	ReviewEndpoint   = "/ptaas/ajax/lory-code-review.php"
	WebScanEndpoint  = "/ptaas/tools/scan-api.php"
	UserAgent        = "Lorikeet-Lory-CLI/1.0"
)

type FindingCallback func(finding types.LoryFinding)

type LoryClient struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

func NewLoryClient(baseURL, token string) *LoryClient {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")

	return &LoryClient{
		BaseURL: baseURL,
		Token:   token,
		HTTPClient: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
			},
		},
	}
}

// ReviewCode sends source code to the Lory code review endpoint
func (c *LoryClient) ReviewCode(ctx context.Context, req types.LoryReviewRequest, onFinding FindingCallback) (*types.LoryReviewResponse, error) {
	url := c.BaseURL + ReviewEndpoint

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if req.Stream && onFinding != nil {
		httpReq.Header.Set("Accept", "text/event-stream")
	} else {
		httpReq.Header.Set("Accept", "application/json")
	}
	httpReq.Header.Set("User-Agent", UserAgent)

	if c.Token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("connection error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("token rejected by Lory (HTTP 401). Run 'lory token set' to update it")
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		retryAfter := resp.Header.Get("Retry-After")
		rateLimit := resp.Header.Get("X-RateLimit-Limit")
		msg := "Lory is rate limiting requests"
		if rateLimit != "" {
			msg += fmt.Sprintf(" (%s/min)", rateLimit)
		}
		if retryAfter != "" {
			msg += fmt.Sprintf(". Retry in %ss", retryAfter)
		}
		if c.Token == "" {
			msg += ". Set a Lory access token ('lory token set <token>') to increase limits."
		}
		return nil, fmt.Errorf("%s", msg)
	}

	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("Lory server error (HTTP %d)", resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Lory returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	contentType := resp.Header.Get("Content-Type")

	// If streaming SSE response
	if strings.Contains(contentType, "text/event-stream") && onFinding != nil {
		return c.readSSEStream(resp.Body, onFinding)
	}

	// Plain JSON response
	var reviewResp types.LoryReviewResponse
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if err := json.Unmarshal(bodyBytes, &reviewResp); err != nil {
		return nil, fmt.Errorf("invalid JSON response from Lory: %w", err)
	}

	if !reviewResp.Success && reviewResp.Error != "" {
		return nil, fmt.Errorf("Lory reported: %s", reviewResp.Error)
	}

	return &reviewResp, nil
}

func (c *LoryClient) readSSEStream(reader io.Reader, onFinding FindingCallback) (*types.LoryReviewResponse, error) {
	scanner := bufio.NewScanner(reader)
	result := &types.LoryReviewResponse{
		Success:  true,
		Findings: make([]types.LoryFinding, 0),
	}

	var currentEvent string
	var currentData strings.Builder

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if currentEvent != "" && currentData.Len() > 0 {
				dataStr := strings.TrimSpace(currentData.String())
				switch currentEvent {
				case "finding":
					var f types.LoryFinding
					if err := json.Unmarshal([]byte(dataStr), &f); err == nil && f.Line > 0 {
						result.Findings = append(result.Findings, f)
						if onFinding != nil {
							onFinding(f)
						}
					}
				case "done":
					var doneData struct {
						Summary string                 `json:"summary"`
						Meta    map[string]interface{} `json:"meta"`
					}
					if err := json.Unmarshal([]byte(dataStr), &doneData); err == nil {
						result.Summary = doneData.Summary
						result.Meta = doneData.Meta
					}
				case "error":
					var errData struct {
						Error string `json:"error"`
					}
					if err := json.Unmarshal([]byte(dataStr), &errData); err == nil && errData.Error != "" {
						return result, fmt.Errorf("Lory stream error: %s", errData.Error)
					}
				}
			}
			currentEvent = ""
			currentData.Reset()
			continue
		}

		if strings.HasPrefix(line, "event:") {
			currentEvent = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		} else if strings.HasPrefix(line, "data:") {
			chunk := strings.TrimPrefix(line, "data:")
			chunk = strings.TrimPrefix(chunk, " ")
			currentData.WriteString(chunk)
		}
	}

	return result, scanner.Err()
}
