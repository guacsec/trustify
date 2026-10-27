import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// Keep manual Trunk builds and Cargo embedding on the same locked dependencies.
const directory = fileURLToPath(new URL('../', import.meta.url));
const hash = createHash('sha256');
for (const file of ['package.json', 'package-lock.json']) {
  hash.update(readFileSync(new URL(`../${file}`, import.meta.url)));
}
hash.update(`${process.platform}/${process.arch}/${process.versions.node}`);
const fingerprint = hash.digest('hex');
const stamp = new URL('../node_modules/.trustify-install', import.meta.url);

if (!existsSync(stamp) || readFileSync(stamp, 'utf8') !== fingerprint) {
  const windows = process.platform === 'win32';
  const result = spawnSync(windows ? 'npm.cmd' : 'npm', ['ci'], {
    cwd: directory,
    stdio: 'inherit',
    shell: windows,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
  mkdirSync(new URL('../node_modules/', import.meta.url), { recursive: true });
  writeFileSync(stamp, fingerprint);
}
