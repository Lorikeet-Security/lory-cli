import { handleLogin, handleLogout, handleWhoAmI } from './commands/auth';
import { handleScan } from './commands/scan';
import { handleRetest } from './commands/retest';
import { handleChat } from './commands/chat';
import { handleMCP } from './commands/mcp';
import { printBanner } from './ui';

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  switch (command) {
    case 'scan':
      await handleScan({ repo: args[1] || '.' });
      break;
    case 'retest':
      await handleRetest(args[1] || 'LOR-0001');
      break;
    case 'chat':
      await handleChat();
      break;
    case 'mcp':
      await handleMCP();
      break;
    case 'login':
      await handleLogin(args[1]);
      break;
    case 'logout':
      handleLogout();
      break;
    case 'whoami':
      handleWhoAmI();
      break;
    default:
      printBanner();
      console.log('Usage: lory <command> [scan, chat, retest, findings, export, mcp, login, logout, whoami]');
      break;
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
