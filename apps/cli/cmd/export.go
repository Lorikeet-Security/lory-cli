package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"strings"

	"github.com/Lorikeet-Security/lory-cli/pkg/auth"
	"github.com/Lorikeet-Security/lory-cli/pkg/badge"
	"github.com/Lorikeet-Security/lory-cli/pkg/export"
	"github.com/Lorikeet-Security/lory-cli/pkg/scanner"
	"github.com/Lorikeet-Security/lory-cli/pkg/tui"
	"github.com/Lorikeet-Security/lory-cli/pkg/types"
)

func RunExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	formatFlag := fs.String("format", "sarif", "Export format: sarif, json, soc2, pdf, badge")
	soc2Flag := fs.Bool("soc2", false, "Include SOC 2 Type II / ISO 27001 compliance evidence attestation")
	outFlag := fs.String("out", "", "File path to save output (defaults to stdout)")
	repoFlag := fs.String("repo", ".", "Repository path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	creds, _ := auth.LoadCredentials()
	orgName := "Lorikeet Organization"
	if creds != nil {
		orgName = creds.OrgName
	}

	findings, _, err := scanner.RunScan(types.ScanConfig{RepoPath: *repoFlag}, nil)
	if err != nil {
		return err
	}

	var outputBytes []byte

	if strings.Contains(*formatFlag, "pdf") {
		outputBytes = export.GeneratePDFEvidence(findings, orgName)
	} else if *soc2Flag || strings.Contains(*formatFlag, "soc2") {
		content := export.GenerateSOC2Evidence(findings, orgName)
		outputBytes = []byte(content)
	} else if strings.Contains(*formatFlag, "badge") {
		badgeOpts := badge.DefaultOptions()
		badgeOpts.OrgName = orgName
		badgeOpts.Target = *repoFlag
		if len(findings) == 0 {
			badgeOpts.Status = "VERIFIED"
			badgeOpts.Score = 100
		} else {
			badgeOpts.Status = "ATTENDED"
			badgeOpts.Score = 90
		}
		outputBytes = []byte(badge.GenerateSVG(badgeOpts))
	} else if strings.Contains(*formatFlag, "json") {
		outputBytes, _ = json.MarshalIndent(findings, "", "  ")
	} else {
		// Default to SARIF 2.1.0
		sarifBytes, err := export.GenerateSARIF(findings)
		if err != nil {
			return err
		}
		outputBytes = sarifBytes
	}

	if *outFlag != "" {
		if err := export.ExportToFile(*outFlag, outputBytes); err != nil {
			return fmt.Errorf("failed to write export file: %w", err)
		}
		fmt.Printf("%s✔ Successfully exported compliance evidence to %s%s\n", tui.ColorGreen, *outFlag, tui.ColorReset)
		return nil
	}

	// Print to stdout
	fmt.Println(string(outputBytes))
	return nil
}
