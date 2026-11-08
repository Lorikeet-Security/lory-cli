import * as http from 'http';
import * as https from 'https';
import * as crypto from 'crypto';
import { exec } from 'child_process';
import { AuthCredentials } from '@lorikeetsecurity/protocol';

export const TALON_OAUTH_AUTH_URL = 'https://lorikeetsecurity.com/talon/mcp/oauth/authorize';
export const TALON_OAUTH_TOKEN_URL = 'https://lorikeetsecurity.com/talon/mcp/oauth/token';
export const TALON_OAUTH_USERINFO_URL = 'https://lorikeetsecurity.com/talon/mcp/oauth/userinfo';
export const DEFAULT_CLIENT_ID = 'nXAJUzhrz6lh6MoWskBKVg';
export const DEFAULT_SCOPE = 'findings:read kb:read compliance:read';

function renderCallbackHTML(userDisplay: string): string {
  const safeUser = userDisplay
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Lorikeet Security — Authentication Successful</title>
  <style>
    :root {
      --primary: #ba5663;
      --primary-light: #db6574;
      --bg: #0a1628;
      --card: #142b49;
      --card-pill: #1a375d;
      --text: #ffffff;
      --text-muted: #94a3b8;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background: radial-gradient(ellipse at top, rgba(186, 86, 99, 0.12), transparent 60%), var(--bg);
      color: var(--text);
      padding: 24px;
    }
    .card {
      width: 100%;
      max-width: 440px;
      background: var(--card);
      border: 1px solid rgba(82, 82, 82, 0.6);
      border-radius: 14px;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.6);
      padding: 36px 32px 32px;
      text-align: center;
    }
    .brand-header {
      display: inline-flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 24px;
    }
    .brand-title {
      font-size: 1.15rem;
      font-weight: 800;
      letter-spacing: -0.01em;
      color: #ffffff;
    }
    .brand-subtitle {
      font-size: 0.72rem;
      font-weight: 700;
      letter-spacing: 0.12em;
      color: var(--primary-light);
      margin-left: 5px;
    }
    h1 {
      font-size: 1.45rem;
      font-weight: 700;
      margin: 0 0 14px;
      color: #ffffff;
      letter-spacing: -0.02em;
    }
    .user-pill {
      display: inline-block;
      background: var(--card-pill);
      border: 1px solid rgba(82, 82, 82, 0.4);
      border-radius: 9999px;
      padding: 8px 18px;
      font-size: 0.88rem;
      color: #cbd5e1;
      margin-bottom: 18px;
      word-break: break-all;
    }
    .user-pill strong {
      color: #ffffff;
      font-weight: 600;
    }
    p {
      margin: 0 0 8px;
      color: var(--text-muted);
      font-size: 0.92rem;
      line-height: 1.55;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      padding: 9px 22px;
      background: linear-gradient(135deg, var(--primary-light), var(--primary));
      color: #ffffff;
      border-radius: 9999px;
      font-size: 0.84rem;
      font-weight: 600;
      margin-top: 24px;
      border: 1px solid var(--primary-light);
      box-shadow: 0 4px 14px rgba(186, 86, 99, 0.4);
      letter-spacing: 0.02em;
    }
    .badge svg {
      width: 14px;
      height: 14px;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="brand-header">
      <svg width="34" height="34" viewBox="0 0 128 128" fill="none" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Lorikeet Security Logo">
        <defs>
          <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#db6574" />
            <stop offset="100%" stop-color="#ba5663" />
          </linearGradient>
          <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
            <feDropShadow dx="0" dy="2" stdDeviation="4" flood-color="#ba5663" flood-opacity="0.35"/>
          </filter>
        </defs>
        <path d="M64 8 L112 28 L112 60 C112 90 90 112 64 120 C38 112 16 90 16 60 L16 28 Z"
              fill="url(#shieldGrad)" stroke="#142b49" stroke-width="2" filter="url(#glow)"/>
        <path d="M64 18 L102 34 L102 58 C102 84 84 102 64 110 C44 102 26 84 26 58 L26 34 Z"
              fill="none" stroke="rgba(255,255,255,0.3)" stroke-width="1.5"/>
        <g transform="translate(64,62) scale(0.72)">
          <ellipse cx="0" cy="8" rx="18" ry="24" fill="#142b49"/>
          <circle cx="0" cy="-22" r="14" fill="#142b49"/>
          <path d="M14 -24 L28 -20 L14 -18 Z" fill="#ffffff" opacity="0.95"/>
          <circle cx="6" cy="-24" r="3" fill="#ffffff"/>
          <circle cx="7" cy="-24" r="1.5" fill="#142b49"/>
          <path d="M-6 -4 Q-30 4 -24 28 L-2 20 Z" fill="rgba(255,255,255,0.2)"/>
          <path d="M-8 28 L-14 44 L0 36 L14 44 L8 28" fill="#142b49"/>
        </g>
      </svg>
      <div>
        <span class="brand-title">Lorikeet</span>
        <span class="brand-subtitle">SECURITY</span>
      </div>
    </div>
    <h1>Authentication Successful</h1>
    <div class="user-pill">Logged in as <strong>${safeUser}</strong></div>
    <p>Your terminal session for <strong>lory</strong> is now securely authenticated with Talon.</p>
    <p>You can safely close this browser window and return to your terminal.</p>
    <div class="badge">
      <svg viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M13.5 4.5L6.5 11.5L3 8" stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      Lorikeet Security Talon Connected
    </div>
  </div>
</body>
</html>`;
}

function postForm(urlStr: string, body: string): Promise<{ statusCode: number; body: string }> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(urlStr);
    const options = {
      hostname: parsed.hostname,
      port: parsed.port || 443,
      path: parsed.pathname + parsed.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
        'Accept': 'application/json',
        'User-Agent': 'Lorikeet-Lory-CLI/1.2.1',
      },
      timeout: 10000,
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => {
        resolve({ statusCode: res.statusCode || 200, body: data });
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Token exchange request timed out'));
    });
    req.write(body);
    req.end();
  });
}

function getJson(urlStr: string, token: string): Promise<{ statusCode: number; data: any }> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(urlStr);
    const options = {
      hostname: parsed.hostname,
      port: parsed.port || 443,
      path: parsed.pathname + parsed.search,
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
        'User-Agent': 'Lorikeet-Lory-CLI/1.2.1',
      },
      timeout: 8000,
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => {
        try {
          resolve({ statusCode: res.statusCode || 200, data: JSON.parse(data) });
        } catch {
          resolve({ statusCode: res.statusCode || 200, data: null });
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Userinfo request timed out'));
    });
    req.end();
  });
}

function parseJwtClaims(token: string): Record<string, any> | null {
  try {
    const parts = token.split('.');
    if (parts.length >= 2) {
      const payload = Buffer.from(parts[1], 'base64url').toString('utf8');
      return JSON.parse(payload);
    }
  } catch {
    // Ignore decoding errors
  }
  return null;
}

export class SSOServer {
  public static async authenticate(preferredPort = 54321): Promise<AuthCredentials> {
    const state = crypto.randomBytes(16).toString('hex');
    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');

    return new Promise((resolve, reject) => {
      const server = http.createServer(async (req, res) => {
        const url = new URL(req.url || '/', `http://127.0.0.1:${preferredPort}`);
        if (url.pathname === '/callback') {
          const incomingState = url.searchParams.get('state');
          const code = url.searchParams.get('code');
          const errorParam = url.searchParams.get('error');

          if (errorParam) {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            res.end(`Authorization error: ${errorParam}`);
            server.close();
            return reject(new Error(`Authorization failed: ${errorParam}`));
          }

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

          const redirectUri = `http://127.0.0.1:${preferredPort}/callback`;
          let userEmail = '';
          let orgName = '';
          let orgID = '';
          let accessToken = '';
          let refreshToken = '';

          try {
            // 1. Exchange authorization code with TalonOAuthTokenURL using PKCE verifier
            const tokenBody = new URLSearchParams({
              grant_type: 'authorization_code',
              client_id: DEFAULT_CLIENT_ID,
              code: code,
              redirect_uri: redirectUri,
              code_verifier: verifier,
            }).toString();

            const tokenRes = await postForm(TALON_OAUTH_TOKEN_URL, tokenBody);
            if (tokenRes.statusCode !== 200) {
              res.writeHead(400, { 'Content-Type': 'text/plain' });
              res.end(`Token exchange error: ${tokenRes.body}`);
              server.close();
              return reject(new Error(`Token exchange failed: HTTP ${tokenRes.statusCode}: ${tokenRes.body}`));
            }

            const tokenData = JSON.parse(tokenRes.body);
            accessToken = tokenData.access_token || '';
            refreshToken = tokenData.refresh_token || `talon_refresh_${crypto.randomBytes(32).toString('hex')}`;

            // 2. Parse token response for user_email, email, company_name, org_name, company_id
            userEmail = tokenData.user_email || tokenData.email || '';
            orgName = tokenData.company_name || tokenData.org_name || '';
            orgID = tokenData.company_id || tokenData.org_id || '';

            // 3. If email is empty, call FetchUserInfo against userinfo endpoint
            if (!userEmail && accessToken) {
              const uinfo = await getJson(TALON_OAUTH_USERINFO_URL, accessToken).catch(() => null);
              if (uinfo && uinfo.data) {
                userEmail = uinfo.data.email || uinfo.data.user_email || '';
                if (!orgName) orgName = uinfo.data.company_name || uinfo.data.org_name || '';
                if (!orgID) orgID = uinfo.data.company_id || uinfo.data.org_id || '';
              }
            }

            // 4. If email is still empty, parse claims from access_token if it's a JWT
            if (!userEmail && accessToken) {
              const claims = parseJwtClaims(accessToken);
              if (claims) {
                userEmail = claims.email || claims.user_email || (claims.sub && claims.sub.includes('@') ? claims.sub : '');
                if (!orgName) orgName = claims.company_name || claims.org_name || '';
                if (!orgID) orgID = claims.company_id || claims.org_id || '';
              }
            }

            // 5. Fail with explicit error if user identity cannot be confirmed
            if (!userEmail) {
              res.writeHead(400, { 'Content-Type': 'text/plain' });
              res.end('Could not confirm user identity from Talon OAuth session: email claim missing');
              server.close();
              return reject(new Error('Could not confirm user identity from Talon OAuth session: email claim missing'));
            }

            if (!orgName) {
              orgName = orgID ? `Lorikeet Org (${orgID})` : 'Lorikeet Security';
            }
            if (!orgID) {
              orgID = 'org_talon_prod';
            }

            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(renderCallbackHTML(userEmail));
            server.close();

            const creds: AuthCredentials = {
              accessToken,
              refreshToken,
              userEmail,
              orgName,
              orgID,
              authMethod: 'sso',
              expiresAt: new Date(Date.now() + 30 * 86400 * 1000).toISOString(),
            };

            resolve(creds);
          } catch (exchangeErr: any) {
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end(`OAuth processing error: ${exchangeErr.message}`);
            server.close();
            reject(exchangeErr);
          }
        }
      });

      server.listen(preferredPort, '127.0.0.1', () => {
        const redirectUri = encodeURIComponent(`http://127.0.0.1:${preferredPort}/callback`);
        const authUrl = `${TALON_OAUTH_AUTH_URL}?response_type=code&client_id=${DEFAULT_CLIENT_ID}&redirect_uri=${redirectUri}&state=${state}&code_challenge=${challenge}&code_challenge_method=S256&scope=${encodeURIComponent(DEFAULT_SCOPE)}`;
        console.log(`\n> Opening browser to authenticate via Talon OAuth...`);
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
