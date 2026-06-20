'use strict';
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const readline = require('readline');
const fs = require('fs');

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

function ask(question) {
  return new Promise(resolve => rl.question(question, resolve));
}

function askPassword(question) {
  return new Promise(resolve => {
    process.stdout.write(question);
    process.stdin.setRawMode(true);
    process.stdin.resume();
    let password = '';
    process.stdin.on('data', function handler(char) {
      char = char.toString();
      if (char === '\r' || char === '\n') {
        process.stdin.setRawMode(false);
        process.stdin.removeListener('data', handler);
        process.stdout.write('\n');
        resolve(password);
      } else if (char === '') {
        process.exit();
      } else if (char === '') {
        if (password.length > 0) { password = password.slice(0, -1); process.stdout.write('\b \b'); }
      } else {
        password += char;
        process.stdout.write('*');
      }
    });
  });
}

async function setup() {
  console.log('\n=== InvestCU29 Backend Setup ===\n');

  const adminEmail    = await ask('Admin email: ');
  const adminPassword = await askPassword('Admin password (hidden): ');

  console.log('\nHashing password...');
  const sessionSecret      = crypto.randomBytes(64).toString('hex');
  const adminPasswordHash  = await bcrypt.hash(adminPassword, 12);

  const appsScriptUrl = await ask('\nApps Script URL: ');
  const finnhubToken  = await ask('Finnhub API token: ');
  const port          = await ask('Port (leave blank for 3001): ') || '3001';

  const env = `# ── Server ───────────────────────────────────────────────────────
PORT=${port}
NODE_ENV=development
FRONTEND_ORIGIN=http://localhost:8099

# ── Session ───────────────────────────────────────────────────────
SESSION_SECRET=${sessionSecret}

# ── Google Apps Script ────────────────────────────────────────────
APPS_SCRIPT_URL=${appsScriptUrl}

# ── Market data ───────────────────────────────────────────────────
FINNHUB_TOKEN=${finnhubToken}

# ── Admin account ─────────────────────────────────────────────────
ADMIN_EMAIL=${adminEmail.trim().toLowerCase()}
ADMIN_PASSWORD_HASH=${adminPasswordHash}
`;

  fs.writeFileSync('.env', env, 'utf8');
  console.log('\n.env created successfully.');
  console.log('Run "npm start" to launch the backend.\n');
  rl.close();
  process.exit(0);
}

setup();
