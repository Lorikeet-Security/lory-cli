import * as readline from 'readline';
import { CodeAnalyzer } from '@lorikeetsecurity/analyzer';

export async function handleMCP(): Promise<void> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false,
  });

  rl.on('line', async (line) => {
    if (!line.trim()) return;
    try {
      const req = JSON.parse(line);
      if (req.method === 'initialize') {
        process.stdout.write(JSON.stringify({
          jsonrpc: '2.0',
          id: req.id,
          result: {
            protocolVersion: '2024-11-05',
            serverInfo: { name: 'lorikeet-lory-mcp', version: '1.0.0' },
            capabilities: { tools: { listChanged: false } },
          },
        }) + '\n');
      } else if (req.method === 'tools/list') {
        process.stdout.write(JSON.stringify({
          jsonrpc: '2.0',
          id: req.id,
          result: {
            tools: [
              {
                name: 'lory_scan',
                description: 'Runs white-box code mapping and verification',
                inputSchema: { type: 'object', properties: { repo_path: { type: 'string' } } },
              },
            ],
          },
        }) + '\n');
      } else if (req.method === 'tools/call') {
        const res = await CodeAnalyzer.analyze(req.params?.arguments?.repo_path || '.');
        process.stdout.write(JSON.stringify({
          jsonrpc: '2.0',
          id: req.id,
          result: {
            content: [{ type: 'text', text: JSON.stringify(res.findings, null, 2) }],
          },
        }) + '\n');
      }
    } catch (err: any) {
      process.stdout.write(JSON.stringify({
        jsonrpc: '2.0',
        error: { code: -32603, message: err?.message || 'Internal error' },
      }) + '\n');
    }
  });
}
