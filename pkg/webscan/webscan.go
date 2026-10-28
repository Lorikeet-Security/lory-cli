package webscan

import (
	"context"

	"github.com/lorikeetsecurity/lory/pkg/client"
	"github.com/lorikeetsecurity/lory/pkg/types"
)

// ScanTargetURL performs web security checks via the Lorikeet platform scan-api endpoint
func ScanTargetURL(rawURL string) (*types.WebScanResult, error) {
	cli := client.NewLoryClient(client.DefaultBaseURL, "")
	return cli.ScanWebTarget(context.Background(), rawURL)
}

// ScanTargetURLWithClient allows passing a custom configured LoryClient
func ScanTargetURLWithClient(ctx context.Context, cli *client.LoryClient, rawURL string) (*types.WebScanResult, error) {
	if cli == nil {
		cli = client.NewLoryClient(client.DefaultBaseURL, "")
	}
	return cli.ScanWebTarget(ctx, rawURL)
}
