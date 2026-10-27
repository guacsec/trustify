import { spawn } from 'node:child_process';
import { readdir } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ui = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const suite = process.argv[2] ?? 'core';
if (!['core', 'capabilities', 'oidc'].includes(suite)) throw new Error('Expected core, capabilities, or oidc');
const runs = (await readdir(join(ui, 'e2e-results'))).filter(name => /^\d+-\d+$/.test(name)).sort();
if (!runs.length) throw new Error('No browser test runs found; run npm run test:e2e first');
const report = join(ui, 'e2e-results', runs.at(-1), 'report', suite);
const child = spawn(process.execPath, [join(ui, 'node_modules/@playwright/test/cli.js'), 'show-report', report], { stdio: 'inherit' });
child.once('error', error => { console.error(error); process.exitCode = 1; });
child.once('exit', code => { process.exitCode = code ?? 1; });
