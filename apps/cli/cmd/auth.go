package cmd

import (
	"flag"
	"fmt"

	"github.com/lorikeetsecurity/lory/pkg/auth"
	"github.com/lorikeetsecurity/lory/pkg/tui"
)

func RunAuth(args []string) error {
	if len(args) == 0 {
		return RunLogin([]string{})
	}

	sub := args[0]
	switch sub {
	case "login":
		return RunLogin(args[1:])
	case "logout":
		return RunLogout(args[1:])
	case "whoami", "status":
		return RunWhoami(args[1:])
	default:
		return fmt.Errorf("unknown auth subcommand: %s (choose login, logout, whoami)", sub)
	}
}

func RunLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	apiKeyFlag := fs.String("api-key", "", "Lorikeet API Key for headless/automated authentication")
	portFlag := fs.Int("port", auth.DefaultSSOPort, "Local callback port for browser OAuth flow")
	ssoURLFlag := fs.String("sso-url", "", "Talon SSO authentication URL (defaults to https://talon.lorikeetsecurity.com/cli/auth)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	tui.PrintBanner()

	if *apiKeyFlag != "" {
		tui.Spin("Validating Lorikeet API key with Talon...", 300)
		creds, err := auth.LoginWithAPIKey(*apiKeyFlag)
		if err != nil {
			return fmt.Errorf("failed to authenticate with API key: %w", err)
		}
		fmt.Printf("\n%s✔ Successfully authenticated via API Key!%s\n", tui.ColorGreen, tui.ColorReset)
		fmt.Printf("  Org:  %s (%s)\n", creds.OrgName, creds.OrgID)
		fmt.Printf("  User: %s\n\n", creds.UserEmail)
		return nil
	}

	// Interactive browser flow
	fmt.Println("Initiating Talon SSO authentication flow...")
	creds, err := auth.LoginSSO(*portFlag, *ssoURLFlag)
	if err != nil {
		return fmt.Errorf("SSO login failed: %w", err)
	}

	fmt.Printf("\n%s✔ Logged in as %s (%s)%s\n", tui.ColorGreen, creds.UserEmail, creds.OrgName, tui.ColorReset)
	fmt.Printf("  Credentials securely saved to ~/.lorikeet/credentials.json\n\n")
	return nil
}

func RunLogout(args []string) error {
	if err := auth.ClearCredentials(); err != nil {
		return fmt.Errorf("failed to clear credentials: %w", err)
	}
	fmt.Printf("%s✔ Successfully logged out of Lorikeet Talon.%s\n", tui.ColorGreen, tui.ColorReset)
	return nil
}

func RunWhoami(args []string) error {
	creds, err := auth.LoadCredentials()
	if err != nil {
		fmt.Printf("%s✗ Not logged in.%s Run 'lory login' or set LORIKEET_API_KEY\n", tui.ColorYellow, tui.ColorReset)
		return nil
	}

	tui.PrintBanner()
	fmt.Printf("%sActive Lorikeet Session:%s\n", tui.ColorBold, tui.ColorReset)
	fmt.Printf("  User:        %s\n", creds.UserEmail)
	fmt.Printf("  Org:         %s (%s)\n", creds.OrgName, creds.OrgID)
	fmt.Printf("  Auth Method: %s\n", creds.AuthMethod)
	fmt.Printf("  Session:     Active (Synced with Talon Graph)\n\n")
	return nil
}
