#!/usr/bin/env node
const { spawn } = require('child_process');

// Terminalden gelen argümanları yakala ve python paketine ilet
const args = process.argv.slice(2);
const child = spawn('hashsmith', args, { stdio: 'inherit', shell: true });

child.on('exit', (code) => {
  process.exit(code);
});