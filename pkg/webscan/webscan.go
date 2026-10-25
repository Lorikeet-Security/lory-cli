package webscan

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/lorikeetsecurity/lory/pkg/types"
)

// ScanTargetURL performs comprehensive web security checks matching ptaas/tools/scan-api.php
func ScanTargetURL(rawURL string) (*types.WebScanResult, error) {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("invalid URL format: %s", rawURL)
	}

	host := parsed.Host

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	startTime := time.Now()
	resp, err := client.Get(rawURL)
	responseTime := time.Since(startTime)

	if err != nil {
		return nil, fmt.Errorf("could not connect to %s: %w", host, err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	body := string(bodyBytes)

	var totalScore float64
	var totalChecks float64

	categories := make([]types.WebScanCategory, 0)

	// 1. Security Headers
	headerChecks := []struct {
		header     string
		name       string
		passDetail string
		failDetail string
		weight     float64
	}{
		{"strict-transport-security", "Strict-Transport-Security (HSTS)", "HSTS is enabled", "HSTS header is missing. Browsers can be tricked into using HTTP.", 1.0},
		{"content-security-policy", "Content-Security-Policy (CSP)", "CSP header is set", "No CSP header found. Site is vulnerable to XSS.", 1.0},
		{"x-frame-options", "X-Frame-Options", "X-Frame-Options is set", "Missing X-Frame-Options. Site may be vulnerable to clickjacking.", 1.0},
		{"x-content-type-options", "X-Content-Type-Options", "nosniff is enabled", "Missing X-Content-Type-Options. Browsers may MIME-sniff responses.", 1.0},
		{"referrer-policy", "Referrer-Policy", "Referrer-Policy is set", "No Referrer-Policy header. Referrer data may leak to third parties.", 1.0},
		{"permissions-policy", "Permissions-Policy", "Permissions-Policy is configured", "No Permissions-Policy header. Browser features are unrestricted.", 1.0},
		{"x-xss-protection", "X-XSS-Protection", "XSS protection header is set", "Missing X-XSS-Protection header (useful for older browsers).", 0.5},
	}

	secChecks := make([]types.WebScanCheck, 0)
	for _, hc := range headerChecks {
		totalChecks += hc.weight
		val := resp.Header.Get(hc.header)
		if val != "" {
			totalScore += hc.weight
			secChecks = append(secChecks, types.WebScanCheck{
				Name:   hc.name,
				Status: "pass",
				Detail: fmt.Sprintf("%s: %s", hc.passDetail, val),
			})
		} else {
			secChecks = append(secChecks, types.WebScanCheck{
				Name:   hc.name,
				Status: "fail",
				Detail: hc.failDetail,
			})
		}
	}
	categories = append(categories, types.WebScanCategory{
		Name:   "Security Headers",
		Icon:   "fa-shield-halved",
		Checks: secChecks,
	})

	// 2. SSL/TLS
	sslChecks := make([]types.WebScanCheck, 0)
	isHTTPS := strings.HasPrefix(rawURL, "https://")
	totalChecks += 1
	if isHTTPS && resp.StatusCode > 0 {
		totalScore += 1
		sslChecks = append(sslChecks, types.WebScanCheck{
			Name:   "HTTPS Enabled",
			Status: "pass",
			Detail: "Site is accessible over HTTPS.",
		})
	} else {
		sslChecks = append(sslChecks, types.WebScanCheck{
			Name:   "HTTPS Enabled",
			Status: "fail",
			Detail: "Site does not appear to support HTTPS.",
		})
	}

	// HTTP -> HTTPS Redirect check
	httpURL := "http://" + host + parsed.RequestURI()
	noRedirectClient := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	httpResp, httpErr := noRedirectClient.Get(httpURL)
	totalChecks += 1
	if httpErr == nil {
		loc := httpResp.Header.Get("Location")
		if httpResp.StatusCode >= 300 && httpResp.StatusCode < 400 && strings.HasPrefix(loc, "https://") {
			totalScore += 1
			sslChecks = append(sslChecks, types.WebScanCheck{
				Name:   "HTTP to HTTPS Redirect",
				Status: "pass",
				Detail: "HTTP requests are redirected to HTTPS.",
			})
		} else {
			status := "fail"
			if isHTTPS {
				status = "warn"
			}
			sslChecks = append(sslChecks, types.WebScanCheck{
				Name:   "HTTP to HTTPS Redirect",
				Status: status,
				Detail: "HTTP does not redirect to HTTPS. Users may connect insecurely.",
			})
		}
		_ = httpResp.Body.Close()
	}

	// TLS Certificate details
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
		totalChecks += 1

		if daysLeft > 30 {
			totalScore += 1
			sslChecks = append(sslChecks, types.WebScanCheck{
				Name:   "Certificate Expiry",
				Status: "pass",
				Detail: fmt.Sprintf("Certificate expires in %d days (%s).", daysLeft, cert.NotAfter.Format("Jan 02, 2006")),
			})
		} else if daysLeft > 0 {
			totalScore += 0.5
			sslChecks = append(sslChecks, types.WebScanCheck{
				Name:   "Certificate Expiry",
				Status: "warn",
				Detail: fmt.Sprintf("Certificate expires in only %d days! Renew soon.", daysLeft),
			})
		} else {
			sslChecks = append(sslChecks, types.WebScanCheck{
				Name:   "Certificate Expiry",
				Status: "fail",
				Detail: "Certificate has expired or could not be verified.",
			})
		}

		sslChecks = append(sslChecks, types.WebScanCheck{
			Name:   "Certificate Issuer",
			Status: "info",
			Detail: cert.Issuer.CommonName,
		})
	}
	categories = append(categories, types.WebScanCategory{
		Name:   "SSL / TLS",
		Icon:   "fa-lock",
		Checks: sslChecks,
	})

	// 3. Cookie Security
	cookieChecks := make([]types.WebScanCheck, 0)
	cookies := resp.Cookies()
	if len(cookies) > 0 {
		for _, c := range cookies {
			issues := make([]string, 0)
			if !c.Secure {
				issues = append(issues, "Secure")
			}
			if !c.HttpOnly {
				issues = append(issues, "HttpOnly")
			}
			if c.SameSite == http.SameSiteDefaultMode || c.SameSite == http.SameSiteNoneMode {
				issues = append(issues, "SameSite")
			}

			totalChecks += 1
			if len(issues) == 0 {
				totalScore += 1
				cookieChecks = append(cookieChecks, types.WebScanCheck{
					Name:   "Cookie: " + c.Name,
					Status: "pass",
					Detail: "Has Secure, HttpOnly, and SameSite flags configured.",
				})
			} else {
				totalScore += float64(3-len(issues)) / 3.0
				status := "warn"
				if len(issues) >= 2 {
					status = "fail"
				}
				cookieChecks = append(cookieChecks, types.WebScanCheck{
					Name:   "Cookie: " + c.Name,
					Status: status,
					Detail: "Missing flags: " + strings.Join(issues, ", "),
				})
			}
		}
	} else {
		cookieChecks = append(cookieChecks, types.WebScanCheck{
			Name:   "Cookies",
			Status: "info",
			Detail: "No cookies were set in the initial response.",
		})
	}
	categories = append(categories, types.WebScanCategory{
		Name:   "Cookie Security",
		Icon:   "fa-cookie-bite",
		Checks: cookieChecks,
	})

	// 4. Server Information Leakage
	serverChecks := make([]types.WebScanCheck, 0)
	totalChecks += 1
	serverHdr := resp.Header.Get("Server")
	if serverHdr == "" {
		totalScore += 1
		serverChecks = append(serverChecks, types.WebScanCheck{
			Name:   "Server Header",
			Status: "pass",
			Detail: "Server header is not exposed.",
		})
	} else if regexp.MustCompile(`[\d.]`).MatchString(serverHdr) {
		serverChecks = append(serverChecks, types.WebScanCheck{
			Name:   "Server Header",
			Status: "fail",
			Detail: "Server header leaks version info: " + serverHdr,
		})
	} else {
		totalScore += 0.5
		serverChecks = append(serverChecks, types.WebScanCheck{
			Name:   "Server Header",
			Status: "warn",
			Detail: "Server header is present: " + serverHdr,
		})
	}

	totalChecks += 1
	poweredBy := resp.Header.Get("X-Powered-By")
	if poweredBy == "" {
		totalScore += 1
		serverChecks = append(serverChecks, types.WebScanCheck{
			Name:   "X-Powered-By",
			Status: "pass",
			Detail: "X-Powered-By header is not exposed.",
		})
	} else {
		serverChecks = append(serverChecks, types.WebScanCheck{
			Name:   "X-Powered-By",
			Status: "fail",
			Detail: "Technology disclosed: " + poweredBy,
		})
	}

	// Tech detection
	techs := make([]string, 0)
	if strings.Contains(strings.ToLower(serverHdr), "nginx") {
		techs = append(techs, "Nginx")
	}
	if strings.Contains(strings.ToLower(serverHdr), "apache") {
		techs = append(techs, "Apache")
	}
	if strings.Contains(strings.ToLower(serverHdr), "cloudflare") {
		techs = append(techs, "Cloudflare")
	}
	if strings.Contains(strings.ToLower(poweredBy), "express") {
		techs = append(techs, "Express.js")
	}
	if strings.Contains(strings.ToLower(poweredBy), "php") {
		techs = append(techs, "PHP")
	}
	if strings.Contains(body, "_next") || strings.Contains(body, "__NEXT_DATA__") {
		techs = append(techs, "Next.js")
	}
	if strings.Contains(body, "wp-content") {
		techs = append(techs, "WordPress")
	}

	if len(techs) > 0 {
		serverChecks = append(serverChecks, types.WebScanCheck{
			Name:   "Technologies Detected",
			Status: "info",
			Detail: strings.Join(techs, ", "),
		})
	}
	categories = append(categories, types.WebScanCategory{
		Name:   "Server & Technology",
		Icon:   "fa-server",
		Checks: serverChecks,
	})

	// 5. Common Files
	fileChecks := make([]types.WebScanCheck, 0)
	baseURL := parsed.Scheme + "://" + host

	// robots.txt
	robotsResp, _ := client.Head(baseURL + "/robots.txt")
	robotsStatus := 0
	if robotsResp != nil {
		robotsStatus = robotsResp.StatusCode
		_ = robotsResp.Body.Close()
	}
	fileChecks = append(fileChecks, types.WebScanCheck{
		Name:   "robots.txt",
		Status: func() string { if robotsStatus == 200 { return "pass" }; return "info" }(),
		Detail: fmt.Sprintf("robots.txt returned HTTP %d.", robotsStatus),
	})

	// security.txt
	totalChecks += 1
	sectxtResp, _ := client.Head(baseURL + "/.well-known/security.txt")
	sectxtStatus := 0
	if sectxtResp != nil {
		sectxtStatus = sectxtResp.StatusCode
		_ = sectxtResp.Body.Close()
	}
	if sectxtStatus == 200 {
		totalScore += 1
		fileChecks = append(fileChecks, types.WebScanCheck{
			Name:   "security.txt",
			Status: "pass",
			Detail: "security.txt is present at .well-known/security.txt.",
		})
	} else {
		fileChecks = append(fileChecks, types.WebScanCheck{
			Name:   "security.txt",
			Status: "warn",
			Detail: "No security.txt found. Consider adding one for vulnerability disclosure.",
		})
	}
	categories = append(categories, types.WebScanCategory{
		Name:   "Common Files",
		Icon:   "fa-file-lines",
		Checks: fileChecks,
	})

	// 6. Best Practices
	bestChecks := make([]types.WebScanCheck, 0)
	totalChecks += 1
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		totalScore += 1
		bestChecks = append(bestChecks, types.WebScanCheck{
			Name:   "HTTP Response",
			Status: "pass",
			Detail: fmt.Sprintf("Site returned HTTP %d.", resp.StatusCode),
		})
	} else {
		bestChecks = append(bestChecks, types.WebScanCheck{
			Name:   "HTTP Response",
			Status: "warn",
			Detail: fmt.Sprintf("Site returned HTTP %d.", resp.StatusCode),
		})
	}

	totalChecks += 1
	secs := responseTime.Seconds()
	if secs < 2.0 {
		totalScore += 1
		bestChecks = append(bestChecks, types.WebScanCheck{
			Name:   "Response Time",
			Status: "pass",
			Detail: fmt.Sprintf("Server responded in %dms.", responseTime.Milliseconds()),
		})
	} else {
		bestChecks = append(bestChecks, types.WebScanCheck{
			Name:   "Response Time",
			Status: "warn",
			Detail: fmt.Sprintf("Server responded in %dms (slow).", responseTime.Milliseconds()),
		})
	}
	categories = append(categories, types.WebScanCategory{
		Name:   "Best Practices",
		Icon:   "fa-magnifying-glass",
		Checks: bestChecks,
	})

	finalScore := int((totalScore / totalChecks) * 100)
	if finalScore > 100 {
		finalScore = 100
	}
	if finalScore < 0 {
		finalScore = 0
	}

	return &types.WebScanResult{
		Score:          finalScore,
		Target:         rawURL,
		ScannedAt:      time.Now().UTC().Format(time.RFC3339),
		ScansRemaining: 99,
		Categories:     categories,
	}, nil
}
