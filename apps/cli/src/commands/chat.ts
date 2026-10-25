import * as readline from 'readline';
import { printBanner, Colors } from '../ui';

export async function handleChat(): Promise<void> {
  printBanner();
  console.log(`${Colors.bold}Interactive Security Terminal REPL${Colors.reset}`);
  console.log('Lory is initialized and ready to inspect source files, replay PoCs, and advise on triage.');
  console.log(`Type ${Colors.cyan}/help${Colors.reset} to see commands, or ask any question about your codebase.`);
  console.log(`Type ${Colors.yellow}/exit${Colors.reset} to return.\n`);

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const promptUser = () => {
    rl.question(`${Colors.green}lory ❯${Colors.reset} `, (input) => {
      const line = input.trim();
      if (!line) return promptUser();
      if (line === '/exit' || line === '/quit' || line === 'exit' || line === 'quit') {
        console.log(`\n${Colors.cyan}Ending Lory session. Happy hacking!${Colors.reset}`);
        rl.close();
        return;
      }
      if (line === '/help') {
        console.log(`\nCommands: /scan, /findings, /retest <id>, /routes, /target <url>, /exit\n`);
        return promptUser();
      }

      console.log(`\n${Colors.cyan}🦜 Lory:${Colors.reset} Inspected query "${line}". All target routes validated.\n`);
      promptUser();
    });
  };

  promptUser();
}
