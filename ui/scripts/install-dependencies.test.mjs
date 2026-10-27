import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

test('install hook reuses dependencies, invalidates inputs, and retries failures', () => {
  const root = mkdtempSync(join(tmpdir(), 'trustify-npm-hook-'));
  try {
    mkdirSync(join(root, 'scripts'));
    const script = join(root, 'scripts', 'install-dependencies.mjs');
    copyFileSync(new URL('./install-dependencies.mjs', import.meta.url), script);
    const manifest = { name: 'hook-test', version: '1.0.0', private: true };
    const lock = { name: manifest.name, version: manifest.version, lockfileVersion: 3,
      packages: { '': { name: manifest.name, version: manifest.version } } };
    writeFileSync(join(root, 'package.json'), JSON.stringify(manifest));
    writeFileSync(join(root, 'package-lock.json'), JSON.stringify(lock));
    const run = () => spawnSync(process.execPath, [script], {
      encoding: 'utf8',
      env: { ...process.env, npm_config_cache: join(root, '.cache'),
        npm_config_audit: 'false', npm_config_fund: 'false', npm_config_offline: 'true' },
    });
    const success = () => {
      const result = run();
      assert.equal(result.status, 0, result.stderr);
    };
    const stamp = join(root, 'node_modules', '.trustify-install');
    const sentinel = join(root, 'node_modules', 'reused-installation');

    success();
    assert.ok(existsSync(stamp));
    writeFileSync(sentinel, 'keep');
    success();
    assert.ok(existsSync(sentinel), 'unchanged inputs must skip npm ci');

    writeFileSync(join(root, 'package.json'), JSON.stringify({ ...manifest, description: 'changed' }));
    success();
    assert.ok(!existsSync(sentinel), 'manifest change must reinstall');
    writeFileSync(sentinel, 'keep');
    writeFileSync(join(root, 'package-lock.json'), JSON.stringify({ ...lock, requires: true }));
    success();
    assert.ok(!existsSync(sentinel), 'lockfile change must reinstall');

    rmSync(join(root, 'node_modules'), { recursive: true });
    success();
    assert.ok(existsSync(stamp), 'missing node_modules must reinstall');
    const previousStamp = readFileSync(stamp, 'utf8');
    writeFileSync(join(root, 'package-lock.json'), 'invalid json');
    assert.notEqual(run().status, 0);
    assert.notEqual(run().status, 0, 'failed installation must be retried');
    assert.equal(readFileSync(stamp, 'utf8'), previousStamp, 'failure must not record success');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
