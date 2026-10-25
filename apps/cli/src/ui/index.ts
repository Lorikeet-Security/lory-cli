import { VulnerabilityFinding, Severity, FindingStatus } from '@lorikeetsecurity/protocol';

export const Colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  gray: '\x1b[90m',
};

export function printBanner(): void {
  console.log(`
  ___  ____  _   _ 
 / _ \\|  _ \\| | | |  ${Colors.cyan}${Colors.bold}LORIKEET SECURITY${Colors.reset}
| | | | |_) | |_| |  ${Colors.dim}Autonomous Hybrid-Intelligence Security Testing${Colors.reset}
| |_| |  _ < \\__, |  ${Colors.green}Talon Synchronization Active${Colors.reset}
 \\___/|_| \\_\\ ___/   ${Colors.gray}v1.0.0${Colors.reset}
`);
}

export function severityBadge(s: Severity): string {
  switch (s) {
    case 'CRITICAL':
      return `${Colors.red}${Colors.bold}[CRITICAL]${Colors.reset}`;
    case 'HIGH':
      return `${Colors.red}${Colors.bold}[ HIGH ]${Colors.reset}`;
    case 'MEDIUM':
      return `${Colors.yellow}${Colors.bold}[MEDIUM]${Colors.reset}`;
    case 'LOW':
      return `${Colors.blue}${Colors.bold}[ LOW  ]${Colors.reset}`;
    default:
      return `${Colors.gray}${Colors.bold}[ INFO ]${Colors.reset}`;
  }
}

export function statusBadge(s: FindingStatus): string {
  switch (s) {
    case 'VERIFIED':
      return `${Colors.red}${Colors.bold}● VERIFIED${Colors.reset}`;
    case 'RESOLVED':
      return `${Colors.green}${Colors.bold}✔ RESOLVED${Colors.reset}`;
    case 'RETESTING':
      return `${Colors.yellow}${Colors.bold}↻ RETESTING${Colors.reset}`;
    case 'REVIEW_REQUESTED':
      return `${Colors.magenta}${Colors.bold}⚑ REVIEW REQUESTED${Colors.reset}`;
    default:
      return `${Colors.cyan}${Colors.bold}○ OPEN${Colors.reset}`;
  }
}

export function renderFindingCard(f: VulnerabilityFinding): void {
  const line = '─'.repeat(76);
  console.log(`\n${Colors.cyan}${line}${Colors.reset}`);
  console.log(` ${severityBadge(f.severity)}  ${Colors.bold}${f.title}${Colors.reset} (${f.id})`);
  console.log(` Status:     ${statusBadge(f.status)}   CVSS: ${Colors.yellow}${f.cvss.toFixed(1)}${Colors.reset}   CWE: ${Colors.cyan}${f.cwe}${Colors.reset}`);
  console.log(` Location:   ${Colors.white}${f.method} ${f.route}${Colors.reset} (Line ${f.sourceLine})`);
  console.log(` Source:     ${Colors.dim}${f.sourceFile}${Colors.reset}`);
  console.log(` Compliance: ${Colors.gray}${f.complianceTags.join(', ')}${Colors.reset}`);

  console.log(`\n ${Colors.bold}Exploit Synthesis PoC:${Colors.reset}`);
  console.log(`   ${Colors.yellow}${f.pocCommand}${Colors.reset}`);

  if (f.pocResponse) {
    console.log(`\n ${Colors.bold}Verified Target Output:${Colors.reset}`);
    console.log(`   ${Colors.dim}${f.pocResponse}${Colors.reset}`);
  }

  console.log(`\n ${Colors.green}Remediation Guidance:${Colors.reset}`);
  console.log(`   ${f.remediation}`);
  console.log(`${Colors.cyan}${line}${Colors.reset}`);
}
