
import * as readline from 'readline';
import {
  isInitialized,
  initializeMasterPassword,
  verifyMasterPassword,
  lockVault,
  isVaultUnlocked,
  changeMasterPassword,
  getCurrentSession,
  vaultStorage,
  generatePassword,
  logInfo,
  logError,
} from './core';

const CLEAR = '\x1b[2J\x1b[H';
const HIDE_CURSOR = '\x1b[?25l';
const SHOW_CURSOR = '\x1b[?25h';

const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  bgBlue: '\x1b[44m',
  bgGreen: '\x1b[42m',
};

let rl: readline.Interface;

function initReadline(): void {
  rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
}

function prompt(question: string): Promise<string> {
  return new Promise(resolve => {
    rl.question(question, answer => {
      resolve(answer.trim());
    });
  });
}

async function promptPassword(question: string): Promise<string> {
  rl.close();

  return new Promise(resolve => {
    const rl2 = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: true
    });

    const stdout = process.stdout;
    const originalWrite = stdout.write.bind(stdout);

    originalWrite(question);

    let passwordMode = true;
    let password = '';

    (stdout as any).write = (chunk: any, encoding?: any, callback?: any) => {
      if (passwordMode && typeof chunk === 'string') {
        if (callback) callback();
        return true;
      }
      return originalWrite(chunk, encoding, callback);
    };

    rl2.question('', (answer) => {
      passwordMode = false;
      (stdout as any).write = originalWrite;
      originalWrite('\n');
      rl2.close();

      initReadline();

      resolve(answer);
    });
  });
}

function print(msg: string, color = colors.reset): void {
  console.log(`${color}${msg}${colors.reset}`);
}

function success(msg: string): void {
  print(`  ✓ ${msg}`, colors.green);
}

function error(msg: string): void {
  print(`  ✗ ${msg}`, colors.red);
}

function info(msg: string): void {
  print(`  ℹ ${msg}`, colors.cyan);
}

function warning(msg: string): void {
  print(`  ⚠ ${msg}`, colors.yellow);
}

function showHeader(): void {
  console.log(CLEAR);
  console.log(colors.cyan + colors.bright);
  console.log('  ╔═══════════════════════════════════════════════════════╗');
  console.log('  ║           🔐 SECURE PASSWORD MANAGER 🔐               ║');
  console.log('  ╚═══════════════════════════════════════════════════════╝');
  console.log(colors.reset);

  const initialized = isInitialized();
  const unlocked = isVaultUnlocked();

  if (!initialized) {
    print('  Status: Not initialized', colors.yellow);
  } else if (unlocked) {
    const session = getCurrentSession();
    print(`  Status: 🔓 Unlocked`, colors.green);
    if (session) {
      print(`  Credentials: ${vaultStorage.getCredentialCount()}`, colors.dim);
    }
  } else {
    print('  Status: 🔒 Locked', colors.red);
  }

  console.log();
}

function showMainMenu(): void {
  const initialized = isInitialized();
  const unlocked = isVaultUnlocked();

  console.log(colors.bright + '  ═══════════════════════════════════════' + colors.reset);
  console.log(colors.bright + '                  MENU' + colors.reset);
  console.log(colors.bright + '  ═══════════════════════════════════════' + colors.reset);
  console.log();

  if (!initialized) {
    console.log('  [1] Create Vault (init)');
    console.log();
    console.log('  [0] Exit');
  } else if (!unlocked) {
    console.log('  [1] Unlock Vault');
    console.log();
    console.log('  [0] Exit');
  } else {
    console.log('  [1] Add Password');
    console.log('  [2] List Passwords');
    console.log('  [3] Search');
    console.log('  [4] View Password');
    console.log('  [5] Edit');
    console.log('  [6] Delete');
    console.log('  [7] Password Generator');
    console.log('  [8] Lock Vault');
    console.log();
    console.log('  [0] Exit');
  }

  console.log();
}

async function waitForKey(msg = 'Press Enter to continue...'): Promise<void> {
  await prompt(`\n  ${colors.dim}${msg}${colors.reset}`);
}

function selectCredentialByChoice(choice: string, credentials: Array<{ id: string; title: string; username: string }>): string | null {
  const num = parseInt(choice);
  if (num > 0 && num <= credentials.length) {
    return credentials[num - 1].id;
  }
  return choice || null;
}

async function promptCredentialSelection(credentials: Array<{ id: string; title: string; username: string }>): Promise<string | null> {
  if (credentials.length === 0) {
    info('No saved passwords.');
    await waitForKey();
    return null;
  }

  credentials.forEach((cred, index) => {
    console.log(`  ${colors.cyan}${index + 1}.${colors.reset} ${cred.title} (${cred.username})`);
  });

  console.log();
  const choice = await prompt('  Enter number (or ID): ');
  return selectCredentialByChoice(choice, credentials);
}

async function handleInit(): Promise<void> {
  showHeader();
  print('\n  === CREATE VAULT ===\n', colors.bright);

  info('Master password requirements:');
  console.log('    • At least 12 characters');
  console.log('    • Uppercase letter (A-Z)');
  console.log('    • Lowercase letter (a-z)');
  console.log('    • Number (0-9)');
  console.log('    • Special character (!@#$%^&*)');
  console.log();

  const password = await promptPassword('  Enter master password: ');
  const confirm = await promptPassword('  Confirm password: ');

  if (password !== confirm) {
    error('Passwords do not match!');
    await waitForKey();
    return;
  }

  info('Creating vault... (may take a few seconds)');

  const result = await initializeMasterPassword(password);

  if (result.success) {
    success('Vault created!');
    success('Vault unlocked.');
  } else {
    error(result.message);
  }

  await waitForKey();
}

async function handleUnlock(): Promise<void> {
  showHeader();
  print('\n  === UNLOCK VAULT ===\n', colors.bright);

  const password = await promptPassword('  Enter master password: ');

  info('Verifying...');

  const result = await verifyMasterPassword(password);

  if (result.success) {
    success('Vault unlocked!');
  } else {
    error('Invalid password!');
  }

  await waitForKey();
}

async function handleAdd(): Promise<void> {
  showHeader();
  print('\n  === ADD PASSWORD ===\n', colors.bright);

  const title = await prompt('  Title (e.g., GitHub): ');
  if (!title) {
    error('Title is required!');
    await waitForKey();
    return;
  }

  const url = await prompt('  URL (optional): ');
  const username = await prompt('  Username/Email: ');

  if (!username) {
    error('Username is required!');
    await waitForKey();
    return;
  }

  console.log();
  const generateNew = await prompt('  Generate password? (y/n): ');

  let password: string;
  if (generateNew.toLowerCase() === 'y') {
    const lengthStr = await prompt('  Password length (default 16): ');
    const length = parseInt(lengthStr) || 16;
    password = generatePassword(length);
    console.log();
    print(`  Generated: ${colors.green}${password}${colors.reset}`);
  } else {
    password = await promptPassword('  Password: ');
  }

  if (!password) {
    error('Password is required!');
    await waitForKey();
    return;
  }

  const category = await prompt('  Category (default General): ') || 'General';
  const notes = await prompt('  Notes (optional): ');

  try {
    const credential = vaultStorage.addCredential({
      title,
      url,
      username,
      password,
      category,
      notes,
    });

    console.log();
    success('Password saved!');
    info(`ID: ${credential.id}`);
  } catch (err) {
    error((err as Error).message);
  }

  await waitForKey();
}

async function handleList(): Promise<void> {
  showHeader();
  print('\n  === PASSWORD LIST ===\n', colors.bright);

  const credentials = vaultStorage.listCredentials();

  if (credentials.length === 0) {
    info('No saved passwords.');
    await waitForKey();
    return;
  }

  console.log(colors.dim + '  ─'.repeat(40) + colors.reset);

  credentials.forEach((cred, index) => {
    console.log(`  ${colors.cyan}${index + 1}.${colors.reset} ${colors.bright}${cred.title}${colors.reset}`);
    console.log(`     ${colors.dim}Username: ${cred.username}${colors.reset}`);
    console.log(`     ${colors.dim}URL: ${cred.url || '-'}${colors.reset}`);
    console.log(`     ${colors.dim}Category: ${cred.category}${colors.reset}`);
    console.log(`     ${colors.dim}ID: ${cred.id}${colors.reset}`);
    console.log();
  });

  console.log(colors.dim + '  ─'.repeat(40) + colors.reset);
  info(`Total: ${credentials.length}`);

  await waitForKey();
}

async function handleSearch(): Promise<void> {
  showHeader();
  print('\n  === SEARCH ===\n', colors.bright);

  const query = await prompt('  Search: ');

  if (!query) {
    return;
  }

  const results = vaultStorage.searchCredentials(query);

  if (results.length === 0) {
    info('Nothing found.');
    await waitForKey();
    return;
  }

  console.log();
  results.forEach((cred, index) => {
    console.log(`  ${colors.cyan}${index + 1}.${colors.reset} ${colors.bright}${cred.title}${colors.reset}`);
    console.log(`     ${colors.dim}Username: ${cred.username} | ID: ${cred.id}${colors.reset}`);
    console.log();
  });

  info(`Found: ${results.length}`);

  await waitForKey();
}

async function handleView(): Promise<void> {
  showHeader();
  print('\n  === VIEW PASSWORD ===\n', colors.bright);

  const credentials = vaultStorage.listCredentials();
  const id = await promptCredentialSelection(credentials);
  
  if (!id) {
    return;
  }

  const credential = vaultStorage.getCredential(id);

  if (!credential) {
    error('Not found!');
    await waitForKey();
    return;
  }

  console.log();
  console.log(colors.dim + '  ─'.repeat(40) + colors.reset);
  console.log(`  ${colors.bright}${credential.title}${colors.reset}`);
  console.log(colors.dim + '  ─'.repeat(40) + colors.reset);
  console.log(`  URL:      ${credential.url || '-'}`);
  console.log(`  Username: ${credential.username}`);
  console.log(`  Password: ${colors.green}${colors.bright}${credential.password}${colors.reset}`);
  console.log(`  Category: ${credential.category}`);
  console.log(`  Notes:    ${credential.notes || '-'}`);
  console.log(colors.dim + '  ─'.repeat(40) + colors.reset);

  for (let i = 10; i > 0; i--) {
    process.stdout.write(`\r  ${colors.yellow}Password hidden in ${i}s...${colors.reset}  `);
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  process.stdout.write('\r  Password hidden.                    \n');
}

async function handleEdit(): Promise<void> {
  showHeader();
  print('\n  === EDIT ===\n', colors.bright);

  const credentials = vaultStorage.listCredentials();
  const id = await promptCredentialSelection(credentials);
  
  if (!id) {
    return;
  }

  const existing = vaultStorage.getCredential(id);

  if (!existing) {
    error('Not found!');
    await waitForKey();
    return;
  }

  console.log();
  info(`Editing: ${existing.title}`);
  info('Press Enter to keep current value');
  console.log();

  const title = await prompt(`  Title [${existing.title}]: `) || undefined;
  const url = await prompt(`  URL [${existing.url || '-'}]: `) || undefined;
  const username = await prompt(`  Username [${existing.username}]: `) || undefined;

  const updatePass = await prompt('  Update password? (y/n): ');
  let password: string | undefined;

  if (updatePass.toLowerCase() === 'y') {
    const genNew = await prompt('  Generate new? (y/n): ');
    if (genNew.toLowerCase() === 'y') {
      password = generatePassword(16);
      print(`  New password: ${colors.green}${password}${colors.reset}`);
    } else {
      password = await promptPassword('  New password: ');
    }
  }

  const category = await prompt(`  Category [${existing.category}]: `) || undefined;
  const notes = await prompt(`  Notes [${existing.notes || '-'}]: `) || undefined;

  try {
    vaultStorage.updateCredential(id, {
      title,
      url,
      username,
      password,
      category,
      notes,
    });

    success('Updated!');
  } catch (err) {
    error((err as Error).message);
  }

  await waitForKey();
}

async function handleDelete(): Promise<void> {
  showHeader();
  print('\n  === DELETE ===\n', colors.bright);

  const credentials = vaultStorage.listCredentials();
  const id = await promptCredentialSelection(credentials);
  
  if (!id) {
    return;
  }

  const confirm = await prompt(`  ${colors.red}Are you sure? (yes/no): ${colors.reset}`);

  if (confirm !== 'yes') {
    info('Cancelled.');
    await waitForKey();
    return;
  }

  if (vaultStorage.deleteCredential(id)) {
    success('Deleted!');
  } else {
    error('Not found!');
  }

  await waitForKey();
}

async function handleGenerator(): Promise<void> {
  showHeader();
  print('\n  === PASSWORD GENERATOR ===\n', colors.bright);

  const lengthStr = await prompt('  Length (default 16): ');
  const length = parseInt(lengthStr) || 16;

  const password = generatePassword(length);

  console.log();
  console.log(colors.dim + '  ─'.repeat(40) + colors.reset);
  console.log(`  ${colors.green}${colors.bright}${password}${colors.reset}`);
  console.log(colors.dim + '  ─'.repeat(40) + colors.reset);

  console.log();
  const another = await prompt('  Generate another? (y/n): ');

  if (another.toLowerCase() === 'y') {
    await handleGenerator();
  }
}

async function handleLock(): Promise<void> {
  lockVault();
  showHeader();
  success('Vault locked!');
  await waitForKey();
}

function selectCredentialByChoice(choice: string, credentials: Array<{ id: string; title: string; username: string }>): string | null {
  const num = parseInt(choice);
  if (num > 0 && num <= credentials.length) {
    return credentials[num - 1].id;
  }
  return choice || null;
}

async function promptCredentialSelection(credentials: Array<{ id: string; title: string; username: string }>): Promise<string | null> {
  if (credentials.length === 0) {
    info('No saved passwords.');
    await waitForKey();
    return null;
  }

  credentials.forEach((cred, index) => {
    console.log(`  ${colors.cyan}${index + 1}.${colors.reset} ${cred.title} (${cred.username})`);
  });

  console.log();
  const choice = await prompt('  Enter number (or ID): ');
  return selectCredentialByChoice(choice, credentials);
}

const UNLOCKED_MENU_HANDLERS: Record<string, () => Promise<void>> = {
  '1': handleAdd,
  '2': handleList,
  '3': handleSearch,
  '4': handleView,
  '5': handleEdit,
  '6': handleDelete,
  '7': handleGenerator,
  '8': handleLock,
};

async function mainLoop(): Promise<void> {
  while (true) {
    showHeader();
    showMainMenu();

    const choice = await prompt('  Select option: ');

    const initialized = isInitialized();
    const unlocked = isVaultUnlocked();

    if (choice === '0') {
      showHeader();
      print('\n  Goodbye!\n', colors.cyan);
      lockVault();
      break;
    }

    if (!initialized && choice === '1') {
      await handleInit();
    } else if (!unlocked && choice === '1') {
      await handleUnlock();
    } else if (unlocked) {
      const handler = UNLOCKED_MENU_HANDLERS[choice];
      if (handler) {
        await handler();
      }
    }
  }
}

async function main(): Promise<void> {
  initReadline();

  try {
    await vaultStorage.initialize();
  } catch (err) {
    console.error('Failed to initialize storage:', err);
  }

  try {
    await mainLoop();
  } catch (err) {
    console.error('Error:', err);
  } finally {
    rl.close();
    process.stdout.write(SHOW_CURSOR);
    process.exit(0);
  }
}

process.on('SIGINT', () => {
  console.log('\n');
  lockVault();
  process.stdout.write(SHOW_CURSOR);
  process.exit(0);
});

main();
