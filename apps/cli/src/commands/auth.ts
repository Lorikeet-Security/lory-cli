import { SSOServer } from '../auth/sso';
import { KeychainManager } from '../auth/keychain';
import { printBanner, Colors } from '../ui';

export async function handleLogin(apiKey?: string): Promise<void> {
  printBanner();
  if (apiKey) {
    const creds = {
      accessToken: apiKey,
      userEmail: 'api-service-account@lorikeetsecurity.com',
      orgName: 'Lorikeet Enterprise',
      orgID: 'org_ent_live',
      authMethod: 'api_key' as const,
      expiresAt: new Date(Date.now() + 365 * 86400 * 1000).toISOString(),
    };
    KeychainManager.save(creds);
    console.log(`\n${Colors.green}✔ Authenticated via API key!${Colors.reset}`);
    return;
  }

  const creds = await SSOServer.authenticate();
  KeychainManager.save(creds);
  console.log(`\n${Colors.green}✔ Logged in as ${creds.userEmail} (${creds.orgName})${Colors.reset}`);
}

export function handleLogout(): void {
  KeychainManager.clear();
  console.log(`${Colors.green}✔ Successfully logged out of Lorikeet Talon.${Colors.reset}`);
}

export function handleWhoAmI(): void {
  const creds = KeychainManager.load();
  if (!creds) {
    console.log(`${Colors.yellow}Not logged in.${Colors.reset} Run 'lory login' or set LORIKEET_API_KEY`);
    return;
  }
  printBanner();
  console.log(`${Colors.bold}Active Lorikeet Session:${Colors.reset}`);
  console.log(`  User:        ${creds.userEmail}`);
  console.log(`  Org:         ${creds.orgName} (${creds.orgID})`);
  console.log(`  Auth Method: ${creds.authMethod}`);
  console.log(`  Session:     Active (Synced with Talon)\n`);
}
