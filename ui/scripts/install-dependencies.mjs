import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// Keep manual Trunk builds and Cargo embedding on the same locked dependencies.
// Usage: install-dependencies.mjs [directory [npm ci arguments...]]
// The directory defaults to the console sources; Cargo passes its staging directory.
const [target, ...npmArguments] = process.argv.slice(2);
const directory = target ? resolve(target) : fileURLToPath(new URL('../', import.meta.url));
const hash = createHash('sha256');
for (const file of ['package.json', 'package-lock.json']) {
  hash.update(readFileSync(join(directory, file)));
}
hash.update(`${process.platform}/${process.arch}/${process.versions.node}`);
hash.update(JSON.stringify(npmArguments));
const fingerprint = hash.digest('hex');
const modules = join(directory, 'node_modules');
const stamp = join(modules, '.trustify-install');

if (!existsSync(stamp) || readFileSync(stamp, 'utf8') !== fingerprint) {
  const windows = process.platform === 'win32';
  const result = spawnSync(windows ? 'npm.cmd' : 'npm', ['ci', ...npmArguments], {
    cwd: directory,
    stdio: 'inherit',
    shell: windows,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
  mkdirSync(modules, { recursive: true });
  writeFileSync(stamp, fingerprint);
}
