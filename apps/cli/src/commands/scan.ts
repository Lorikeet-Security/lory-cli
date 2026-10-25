import { CodeAnalyzer } from '@lorikeetsecurity/analyzer';
import { KeychainManager } from '../auth/keychain';
import { printBanner, renderFindingCard, Colors, severityBadge } from '../ui';

export async function handleScan(options: { repo: string; target?: string; format?: string; dryRun?: boolean }): Promise<void> {
  const format = options.format || 'table';
  if (format === 'table') {
    printBanner();
  }

  const creds = KeychainManager.load();
  if (format === 'table') {
    if (creds) {
      console.log(`${Colors.dim}[Session]${Colors.reset} Authenticated as ${Colors.cyan}${creds.userEmail}${Colors.reset} (${creds.orgName})`);
    } else {
      console.log(`${Colors.dim}[Session]${Colors.reset} Local unauthenticated mode (Run 'lory login' to sync with Talon)`);
    }
    console.log(`\n${Colors.bold}Starting Autonomous Dual-Validation Pentest${Colors.reset}`);
    console.log(`• Source Repo:   ${Colors.white}${options.repo}${Colors.reset}`);
    console.log(`• Target URL:    ${options.target || 'None specified (white-box mode)'}\n`);
  }

  const result = await CodeAnalyzer.analyze(options.repo);

  if (format === 'json') {
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  console.log(`  ${Colors.cyan}•${Colors.reset} Discovered ${result.routes.length} endpoints across ${result.totalFiles} files (${result.frameworks.join(', ') || 'clean'})`);

  console.log(`\n${Colors.bold}=== Dual-Validated Findings (${result.findings.length}) ===${Colors.reset}`);
  for (const f of result.findings) {
    renderFindingCard(f);
  }

  console.log(`\n${Colors.bold}Pentest Summary:${Colors.reset}`);
  console.log(`  Total Endpoints:   ${result.routes.length}`);
  console.log(`  Files Analyzed:    ${result.totalFiles}`);
  console.log(`  Confirmed Issues:  ${result.findings.length} findings verified`);
}
