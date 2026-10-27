import { spawn } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer as createHttpServer } from 'node:http';
import { createServer as createNetServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

const ui = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const root = resolve(ui, '..');
const runId = `${Date.now()}-${process.pid}`;
const externalDatabasePort = process.env.E2E_EXTERNAL_DB_PORT;
if (externalDatabasePort !== undefined &&
    (!/^\d+$/.test(externalDatabasePort) || Number(externalDatabasePort) < 1 || Number(externalDatabasePort) > 65535)) {
  throw new Error('E2E_EXTERNAL_DB_PORT must be a port between 1 and 65535');
}
const output = join(ui, 'e2e-results', runId);
const logs = join(output, 'logs');
const project = `trustify-ui-e2e-${runId}`;
const suites = ['core', 'capabilities', 'oidc'];
const args = process.argv.slice(2);
const selection = args.find(arg => arg.startsWith('--suite='));
const selected = selection ? [selection.slice('--suite='.length)] : suites;
const forwarded = args.filter(arg => arg !== selection);
if (selected.some(suite => !suites.includes(suite))) {
  throw new Error('Expected --suite=core, --suite=capabilities, or --suite=oidc');
}
if (forwarded.some(arg => /^--(project|config|workers|shard)(=|$)/.test(arg))) {
  throw new Error('The runner owns project/config/workers/shard; select a suite with --suite=');
}

await mkdir(logs, { recursive: true });
const scratch = await mkdtemp(join(tmpdir(), 'trustify-ui-e2e-'));
const children = new Set();
const streams = [];
const reservations = new Map();
const controller = new AbortController();
let composeStarted = false;
const externalDatabases = [];
let fixtureServer;
let interrupted = false;

// Do not inherit a developer's database, OIDC, sample-data, or service configuration.
const env = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
  !/^(TRUSTD_|TRUSTIFY_|AUTH_|AUTHENTICATOR_|UI_|OIDC_|DEVMODE$|SAMPLE_DATA$|EMBEDDED_OIDC$|HTTP_SERVER_|INFRASTRUCTURE_|IMPORTER_|EXPLOIT_INTELLIGENCE_|TRUNK_|MIGRATION_)/.test(key)));
// Let `podman compose` select the user's configured provider (including Docker Compose).
// An explicit PODMAN_COMPOSE_PROVIDER, if set, is already preserved in env.
env.RUST_LOG = 'info,sqlx=error,sea_orm=error';
env.E2E_OUTPUT_DIR = output;

function start(command, commandArgs, name, options = {}) {
  const log = createWriteStream(join(logs, `${name}.log`), { flags: 'a' });
  streams.push(log);
  const child = spawn(command, commandArgs, {
    cwd: root, env, detached: process.platform !== 'win32',
    stdio: ['ignore', 'pipe', 'pipe'], ...options,
  });
  children.add(child);
  child.stdout.pipe(log, { end: false });
  child.stderr.pipe(log, { end: false });
  if (/^(playwright|build|trunk)/.test(name)) {
    child.stdout.pipe(process.stdout, { end: false });
    child.stderr.pipe(process.stderr, { end: false });
  }
  child.result = new Promise((resolveResult, reject) => {
    child.once('error', error => { child.spawnError = error; children.delete(child); reject(error); });
    child.once('exit', (code, signal) => resolveResult({ code, signal }));
  });
  // A background process can fail before its readiness check starts.
  child.result.catch(() => {});
  child.once('exit', () => children.delete(child));
  return child;
}

async function run(command, commandArgs, name, options) {
  const result = await start(command, commandArgs, name, options).result;
  if (result.code !== 0) {
    const tail = await readFile(join(logs, `${name}.log`), 'utf8').catch(() => '');
    throw new Error(`${name} failed (${result.code ?? result.signal}); logs: ${logs}${name.startsWith('playwright') ? '' : '\n' + tail.slice(-3000)}`);
  }
}

function compose(commandArgs, name, options) {
  return run('podman', ['compose', '-f', join(ui, 'e2e/compose.yaml'), '-p', project, ...commandArgs], name, options);
}

function postgres(command, commandArgs, name) {
  if (externalDatabasePort === undefined) {
    return compose(['exec', '-T', 'postgres', command, '-U', 'postgres', ...commandArgs], name);
  }
  return run(command, ['-h', '127.0.0.1', '-p', externalDatabasePort, '-U', 'postgres', ...commandArgs], name,
    { env: { ...env, PGPASSWORD: 'trustify-e2e' } });
}

const stops = new WeakMap();
function stop(child) {
  if (!child) return Promise.resolve();
  if (!stops.has(child)) stops.set(child, stopChild(child));
  return stops.get(child);
}

async function stopChild(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const kill = signal => {
    try {
      if (process.platform === 'win32') child.kill(signal);
      else process.kill(-child.pid, signal);
    } catch (error) {
      if (error.code === 'EPERM') child.kill(signal);
      else if (error.code !== 'ESRCH') throw error;
    }
  };
  kill('SIGTERM');
  let timer;
  try {
    await Promise.race([child.result, new Promise(resolveTimeout => {
      timer = setTimeout(() => { kill('SIGKILL'); resolveTimeout(); }, 5000);
    })]);
  } finally { clearTimeout(timer); }
}

async function waitFor(description, check, child, timeout = 60_000) {
  const deadline = Date.now() + timeout;
  let lastError;
  while (Date.now() < deadline) {
    controller.signal.throwIfAborted();
    if (child?.spawnError) throw child.spawnError;
    if (child && (child.exitCode !== null || child.signalCode !== null)) {
      throw new Error(`${description}: service exited before becoming ready; logs: ${logs}`);
    }
    try { if (await check()) return; } catch (error) { lastError = error; }
    await delay(250, undefined, { signal: controller.signal });
  }
  throw new Error(`Timed out waiting for ${description}: ${lastError?.message ?? 'not ready'}; logs: ${logs}`);
}

async function ready(url, child, timeout) {
  await waitFor(url, async () => (await fetch(url, { signal: AbortSignal.timeout(2000) })).ok, child, timeout);
}

async function releasePort(name) {
  const sockets = reservations.get(name) ?? [];
  reservations.delete(name);
  await Promise.all(sockets.map(socket => new Promise(resolveClose => socket.close(resolveClose))));
}

async function reservePort(name, dualLoopback = false) {
  for (let attempt = 0; attempt < 20; attempt++) {
    const sockets = [];
    reservations.set(name, sockets);
    try {
      for (const host of dualLoopback ? ['127.0.0.1', '::1'] : ['127.0.0.1']) {
        const socket = createNetServer(connection => connection.destroy());
        await new Promise((resolveListen, reject) => {
          socket.once('error', reject);
          socket.listen({ port: sockets[0]?.address().port ?? 0, host, ipv6Only: true }, resolveListen);
        });
        sockets.push(socket);
      }
      return sockets[0].address().port;
    } catch (error) {
      if (sockets.length && ['EADDRNOTAVAIL', 'EAFNOSUPPORT'].includes(error.code)) return sockets[0].address().port;
      await releasePort(name);
      if (error.code !== 'EADDRINUSE') throw error;
    }
  }
  throw new Error(`Unable to reserve a free loopback port for ${name}`);
}

function interrupt(signal) {
  interrupted = true;
  controller.abort(new Error(`Interrupted by ${signal}`));
  // Wake a pending build/test wait immediately; finally handles infrastructure.
  for (const child of children) void stop(child).catch(error => console.error(error));
}
process.once('SIGINT', () => interrupt('SIGINT'));
process.once('SIGTERM', () => interrupt('SIGTERM'));

try {
  // Hold reservations until immediately before each service binds, avoiding
  // duplicate allocations and minimizing the port handoff race with other runs.
  const ports = {};
  for (const name of ['api', 'ui', 'fixtures', 'oidc']) ports[name] = await reservePort(name, name === 'ui');
  ports.database = externalDatabasePort === undefined ? await reservePort('database') : Number(externalDatabasePort);
  env.E2E_DB_PORT = String(ports.database);
  env.E2E_API_URL = `http://127.0.0.1:${ports.api}`;
  env.E2E_UI_URL = `http://localhost:${ports.ui}`;
  env.E2E_FIXTURE_URL = `http://127.0.0.1:${ports.fixtures}`;
  env.E2E_OIDC_URL = `http://127.0.0.1:${ports.oidc}/realms/trustify`;
  await writeFile(join(logs, 'ports.json'), JSON.stringify({ project, ...ports }, null, 2));
  console.log(`[e2e] Allocated ports: ${JSON.stringify(ports)}`);
  if (externalDatabasePort === undefined) {
    await run('podman', ['info', '--format', '{{.Host.Arch}}'], 'podman-info');
    await compose(['version'], 'compose-version');
  }
  if (!process.env.E2E_SKIP_BUILD) {
    await run('cargo', ['build', '--locked', '-p', 'trustify-trustd', '--no-default-features', '--features', 'garage-door'], 'build-backend');
  }
  const binary = resolve(process.env.CARGO_TARGET_DIR ?? join(root, 'target'), 'debug/trustd');
  fixtureServer = createHttpServer(async (request, response) => {
    try {
      const path = new URL(request.url, env.E2E_FIXTURE_URL).pathname;
      if (path === '/health') { response.end('ok'); return; }
      const repository = /^\/([a-z0-9-]+)\/(PULP_MANIFEST|document\.json)$/.exec(path);
      if (repository) {
        const suffix = repository[2] === 'PULP_MANIFEST' ? 'manifest' : 'json';
        const body = await readFile(join(scratch, 'fixtures', `${repository[1]}.${suffix}`));
        response.writeHead(200, { 'content-type': suffix === 'json' ? 'application/json' : 'text/plain' }).end(body);
        return;
      }
      // An explicit allowlist prevents this fixture server exposing unrelated files.
      if (!/^\/[a-z0-9-]+\.json$/.test(path)) { response.writeHead(404).end(); return; }
      const body = await readFile(join(scratch, 'fixtures', path.slice(1)));
      response.writeHead(200, { 'content-type': 'application/json' }).end(body);
    } catch { response.writeHead(404).end(); }
  });
  await mkdir(join(scratch, 'fixtures'));
  env.E2E_FIXTURE_DIR = join(scratch, 'fixtures');
  await new Promise((resolveListen, reject) => {
    fixtureServer.once('error', reject);
    releasePort('fixtures').then(() => fixtureServer.listen(ports.fixtures, '127.0.0.1', resolveListen), reject);
  });
  if (externalDatabasePort === undefined) {
    await releasePort('database');
    composeStarted = true; // Cleanup also covers partially successful `up`.
    await compose(['up', '-d'], 'compose-up');
  }
  await waitFor('PostgreSQL', async () => {
    try {
      await postgres('pg_isready', ['-d', 'postgres'], 'postgres-ready');
      return true;
    } catch { return false; }
  });
  // Trunk's development server can stay alive after a failed build and serve stale
  // assets. Require a successful build before accepting its readiness response.
  const trunkConfig = join(scratch, 'Trunk.toml');
  await writeFile(trunkConfig, [
    '[build]', `target = ${JSON.stringify(join(ui, 'index.html'))}`, `dist = ${JSON.stringify(join(scratch, 'dist'))}`,
    '[watch]', `watch = ${JSON.stringify(['src', 'assets', 'index.html', 'Cargo.toml'].map(path => join(ui, path)))}`,
    '[serve]', 'addresses = ["127.0.0.1"]', `port = ${ports.ui}`, 'no_autoreload = true',
    ...['/api/', '/.well-known/', '/swagger-ui/', '/openapi.json'].flatMap(path => [
      '[[proxy]]', `rewrite = ${JSON.stringify(path)}`, `backend = ${JSON.stringify(env.E2E_API_URL + path)}`,
    ]),
  ].join('\n'));
  await run('trunk', ['build', '--config', trunkConfig, '--locked'], 'build-ui', { cwd: ui });
  await releasePort('ui');
  const trunk = start('trunk', ['serve', '--config', trunkConfig, '--locked', '--no-autoreload'], 'trunk', { cwd: ui });
  await ready(env.E2E_UI_URL, trunk, 600_000);
  const failures = [];
  let testsRun = 0;
  for (const suite of selected) {
    console.log(`[e2e] Starting ${suite} suite`);
    controller.signal.throwIfAborted();
    const database = `e2e_${suite}_${runId.replaceAll('-', '_')}`;
    const storage = join(scratch, suite, 'storage');
    await mkdir(storage, { recursive: true });
    const serviceEnv = {
      ...env, E2E_SUITE: suite,
      TRUSTD_DB_HOST: '127.0.0.1', TRUSTD_DB_PORT: env.E2E_DB_PORT,
      TRUSTD_DB_NAME: database, TRUSTD_DB_USER: 'postgres', TRUSTD_DB_PASSWORD: 'trustify-e2e',
      TRUSTD_STORAGE_FS_PATH: storage,
      TRUSTD_DB_MIN_CONN: '1', TRUSTD_DB_MAX_CONN: '10',
    };
    if (suite === 'oidc') {
      // Use an explicit IPv4 issuer consistently in the browser and authenticator.
      // The embedded server binds the same address as the API; this also avoids
      // accidentally discovering an unrelated development issuer on IPv6 localhost.
      serviceEnv.TRUSTD_ISSUER_URL = env.E2E_OIDC_URL;
      serviceEnv.UI_ISSUER_URL = serviceEnv.TRUSTD_ISSUER_URL;
    }
    await postgres('createdb', [database], `create-${suite}`);
    if (externalDatabasePort !== undefined) externalDatabases.push(database);
    await run(binary, ['db', 'migrate'], `migrate-${suite}`, { env: serviceEnv });
    const flags = suite === 'oidc' ? ['--embedded-oidc'] : ['--auth-disabled'];
    if (suite === 'capabilities') flags.push('--disable-correlation');
    await releasePort('api');
    if (suite === 'oidc') await releasePort('oidc');
    const api = start(binary, ['api', ...flags, '--http-server-bind-address', '127.0.0.1', '--http-server-bind-port', String(ports.api)], `api-${suite}`, { env: serviceEnv });
    let importer;
    try {
      await ready(`${env.E2E_API_URL}/.well-known/trustify`, api);
      if (suite === 'oidc') await ready(`${env.E2E_OIDC_URL}/.well-known/openid-configuration`, api);
      if (suite === 'core') {
        importer = start(binary, ['importer', '--working-dir', join(scratch, 'importer')], 'importer', { env: serviceEnv });
      }
      try {
        await run(process.execPath, [join(ui, 'node_modules/@playwright/test/cli.js'), 'test', '--project', suite,
          ...(selected.length > 1 ? ['--pass-with-no-tests'] : []), ...forwarded], `playwright-${suite}`, { cwd: ui, env: serviceEnv });
        const junit = await readFile(join(output, `${suite}.xml`), 'utf8');
        const count = /<testsuites\b[^>]*\btests="(\d+)"/.exec(junit);
        if (!count) throw new Error(`Missing test count in ${suite} JUnit report`);
        testsRun += Number(count[1]);
      } catch (error) { failures.push(error.message); }
    } finally { await stop(importer); await stop(api); }
  }
  if (failures.length) throw new Error(failures.join('\n'));
  if (!testsRun) throw new Error('No tests matched the supplied filter');
} catch (error) {
  console.error(error);
  process.exitCode = interrupted ? 130 : 1;
} finally {
  await Promise.allSettled([...children].map(stop));
  await Promise.allSettled([...reservations.keys()].map(releasePort));
  if (fixtureServer?.listening) await new Promise(resolveClose => fixtureServer.close(resolveClose));
  for (const database of externalDatabases) {
    try { await postgres('dropdb', [database], `drop-${database}`); }
    catch (error) { console.error(error.message); process.exitCode = 1; }
  }
  if (composeStarted) {
    try { await compose(['logs', '--no-color'], 'postgres'); } catch (error) { console.error(error.message); }
    try { await compose(['down', '--volumes', '--remove-orphans'], 'compose-down'); }
    catch (error) { console.error(error.message); process.exitCode = 1; }
  }
  await rm(scratch, { recursive: true, force: true });
  await Promise.all(streams.map(stream => new Promise(resolveEnd => stream.end(resolveEnd))));
  console.log(`E2E logs: ${logs}`);
}
