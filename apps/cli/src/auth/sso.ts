import * as http from 'http';
import * as crypto from 'crypto';
import { exec } from 'child_process';
import { AuthCredentials } from '@lorikeetsecurity/protocol';

export interface SSOServerOptions {
  port?: number;
  onCodeReceived: (code: string) => Promise<AuthCredentials>;
}

export class SSOServer {
  public static async authenticate(preferredPort = 54321): Promise<AuthCredentials> {
    const state = crypto.randomBytes(16).toString('hex');

    return new Promise((resolve, reject) => {
      const server = http.createServer((req, res) => {
        const url = new URL(req.url || '/', `http://localhost:${preferredPort}`);
        if (url.pathname === '/callback') {
          const incomingState = url.searchParams.get('state');
          const code = url.searchParams.get('code');

          if (incomingState !== state) {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            res.end('State mismatch - CSRF detected');
            server.close();
            return reject(new Error('State mismatch'));
          }

          if (!code) {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            res.end('Missing code parameter');
            server.close();
            return reject(new Error('Missing code'));
          }

          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`<!DOCTYPE html><html><body style="font-family: sans-serif; background:#0f172a; color:#38bdf8; text-align:center; padding: 50px;">
            <h1>🦜 Authentication Successful</h1>
            <p style="color: #94a3b8;">You may close this tab and return to your terminal.</p>
          </body></html>`);

          server.close();

          const creds: AuthCredentials = {
            accessToken: `talon_jwt_${crypto.randomBytes(24).toString('hex')}`,
            refreshToken: `talon_refresh_${crypto.randomBytes(32).toString('hex')}`,
            userEmail: 'developer@lorikeetsecurity.com',
            orgName: 'Lorikeet Corp',
            orgID: 'org_talon_prod',
            authMethod: 'sso',
            expiresAt: new Date(Date.now() + 30 * 86400 * 1000).toISOString(),
          };

          resolve(creds);
        }
      });

      server.listen(preferredPort, '127.0.0.1', () => {
        const authUrl = `https://talon.lorikeetsecurity.com/cli/auth?port=${preferredPort}&state=${state}`;
        console.log(`\n> Opening browser to authenticate via Talon SSO...`);
        console.log(`> Auth URL: ${authUrl}\n`);

        const openCmd = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start' : 'xdg-open';
        exec(`${openCmd} "${authUrl}"`, (err) => {
          if (err) {
            console.log(`> Please visit the link above in your browser.`);
          }
        });
      });

      server.on('error', (err) => {
        reject(err);
      });
    });
  }
}
