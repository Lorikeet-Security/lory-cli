import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { AuthCredentials } from '@lorikeetsecurity/protocol';

export class KeychainManager {
  private static getPath(): string {
    const candidates = [
      path.join(os.homedir(), '.lorikeet'),
      process.env.XDG_CONFIG_HOME ? path.join(process.env.XDG_CONFIG_HOME, 'lorikeet') : null,
      path.join(process.cwd(), '.lorikeet'),
      path.join(os.tmpdir(), '.lorikeet'),
    ].filter(Boolean) as string[];

    for (const dir of candidates) {
      try {
        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
        }
        return path.join(dir, 'credentials.json');
      } catch {
        continue;
      }
    }
    return path.join(os.tmpdir(), 'credentials.json');
  }

  public static load(): AuthCredentials | null {
    if (process.env.LORIKEET_API_KEY) {
      return {
        accessToken: process.env.LORIKEET_API_KEY,
        userEmail: 'ci-runner@lorikeetsecurity.com',
        orgName: 'Headless CI Environment',
        orgID: 'org_headless_ci',
        authMethod: 'api_key',
        expiresAt: new Date(Date.now() + 365 * 86400 * 1000).toISOString(),
      };
    }

    const filePath = this.getPath();
    if (!fs.existsSync(filePath)) return null;

    try {
      const data = fs.readFileSync(filePath, 'utf8');
      return JSON.parse(data);
    } catch {
      return null;
    }
  }

  public static save(creds: AuthCredentials): void {
    const filePath = this.getPath();
    fs.writeFileSync(filePath, JSON.stringify(creds, null, 2), { mode: 0o600 });
  }

  public static clear(): void {
    const filePath = this.getPath();
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  }
}
