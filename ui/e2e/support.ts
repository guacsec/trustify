import { test as base, expect, type APIRequestContext, type Page, type Locator } from '@playwright/test';
import { createHash, randomUUID } from 'node:crypto';
import { readFile, writeFile, unlink } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

// No fallback target: the runner supplies an isolated, dynamically allocated API.
export const apiURL = process.env.E2E_API_URL!;
export const scenarioDir = resolve(__dirname, '../../etc/test-data/scenarios');
export const urllib3 = 'S6_positive_baseline_osv_urllib3';
export const openssl = 'S5_positive_baseline_openssl_el8';

export type Seed = {
  affected: string;
  patched: string;
  belowFix: string;
  atFix: string;
  osv: string;
  cve: string;
  csaf: string;
};

export function uuid(id: string): string { return id.replace(/^urn:uuid:/, ''); }

export async function document(path: string): Promise<Buffer> {
  const filename = resolve(scenarioDir, path);
  return path.endsWith('.xz') ? execFileSync('xz', ['-dc', filename]) : readFile(filename);
}

export async function upload(request: APIRequestContext, data: Buffer): Promise<string> {
  const response = await request.post(`${apiURL}/api/v3/upload`, {
    data, headers: { 'content-type': 'application/octet-stream' },
  });
  expect(response.ok(), await response.text()).toBeTruthy();
  return uuid((await response.json()).id);
}

async function seedData(request: APIRequestContext): Promise<Seed> {
  const ingest = async (path: string) => upload(request, await document(path));
  const osv = await ingest(`${urllib3}/osv/GHSA-g4mx-q9vg-27p4.json`);
  const cve = await ingest(`${urllib3}/cve/CVE-2023-45803.json`);
  const csaf = await ingest(`${openssl}/vex/CVE-2022-4304.json.xz`);
  await ingest(`${openssl}/vex/CVE-2023-0215.json.xz`);
  // These preserve the scenarios' identifiers, versions, and expected verdicts.
  const affected = await ingest(`${urllib3}/sbom_urllib3_affected.cdx.json`);
  const patched = await ingest(`${urllib3}/sbom_urllib3_patched.cdx.json`);
  const belowFix = await ingest(`${openssl}/sbom_openssl_el8_below-fix.cdx.json`);
  const atFix = await ingest(`${openssl}/sbom_openssl_el8_at-fix.cdx.json`);
  if (process.env.E2E_SUITE !== 'capabilities') {
    // Duplicate fixture ingestion also queues background work. Drain it before
    // tests invalidate settings, otherwise late extraction can clear the backlog
    // before the refresh UI has a chance to observe it.
    await expect.poll(async () => {
      const response = await request.get(`${apiURL}/api/v3/correlation/freshness`);
      const data = await response.json();
      return data.extraction_lag?.pending_advisories + data.extraction_lag?.pending_sboms;
    }, { timeout: 60_000 }).toBe(0);
    await expect.poll(async () => {
      const response = await request.get(`${apiURL}/api/v3/correlation/sbom/${affected}`);
      if (!response.ok()) return [];
      return (await response.json()).verdicts.map((verdict: { status: string }) => verdict.status);
    }, { timeout: 60_000 }).toContain('affected');
    await expect.poll(async () => {
      const response = await request.get(`${apiURL}/api/v3/correlation/sbom/${atFix}`);
      return response.ok() ? (await response.json()).verdicts.map((v: { status: string }) => v.status) : [];
    }, { timeout: 60_000 }).toContain('fixed');
  }
  return { affected, patched, belowFix, atFix, osv, cve, csaf };
}

type OwnedData = {
  sboms: string[];
  advisories: string[];
  importers: string[];
  options: string[];
  aliases: string[];
  files: string[];
};

export const test = base.extend<{ owned: OwnedData; guard: void; allowedApiErrors: string[] }, { seed: Seed }>({
  allowedApiErrors: async ({}, use) => { await use([]); },
  seed: [async ({ playwright }, use) => {
    const request = await playwright.request.newContext();
    try { await use(await seedData(request)); } finally { await request.dispose(); }
  }, { scope: 'worker' }],
  owned: async ({ request }, use) => {
    const owned: OwnedData = { importers: [], sboms: [], advisories: [], options: [], aliases: [], files: [] };
    try { await use(owned); } finally {
      const errors: string[] = [];
      for (const [kind, ids] of Object.entries(owned)) {
        for (const id of ids) {
          if (kind === 'files') { await unlink(id).catch(() => {}); continue; }
          const path = kind === 'sboms' ? `/v3/sbom/urn:uuid:${uuid(id)}`
            : kind === 'advisories' ? `/v3/advisory/urn:uuid:${uuid(id)}`
            : kind === 'importers' ? `/v3/importer/${encodeURIComponent(id)}`
            : kind === 'options' ? `/v3/correlation/option/${id}`
            : `/v3/correlation/provider-alias/${id}`;
          const response = await request.delete(`${apiURL}/api${path}`);
          if (!response.ok() && response.status() !== 404) errors.push(`${path}: ${response.status()} ${await response.text()}`);
        }
      }
      expect(errors, 'Test resource cleanup').toEqual([]);
    }
  },
  guard: [async ({ page, allowedApiErrors }, use, testInfo) => {
    const errors: string[] = [];
    const networkErrors: string[] = [];
    const allowed = (url: string) => allowedApiErrors.some(path => new URL(url).pathname === path);
    page.on('response', response => {
      if (response.status() >= 400 && /\/(api\/|\.well-known\/)/.test(response.url()) && !allowed(response.url())) {
        networkErrors.push(`${response.status()} ${response.request().method()} ${response.url()}`);
      }
    });
    page.on('requestfailed', request => {
      if (request.url().includes('/api/') && request.failure()?.errorText !== 'net::ERR_ABORTED' && !allowed(request.url())) {
        networkErrors.push(`${request.failure()?.errorText} ${request.url()}`);
      }
    });
    page.on('pageerror', error => errors.push(error.message));
    page.on('console', message => {
      if (message.type() === 'error') errors.push(message.text());
    });
    await use();
    if (testInfo.status === testInfo.expectedStatus && !page.isClosed()) {
      await expect(page.locator('[aria-label="Application panicked"]')).toHaveCount(0);
      // HTTP failures are asserted explicitly by the failure-injection tests.
      expect(errors.filter(message => !/Failed to load resource|net::ERR_|status of (400|404|409|412|422|500|503)/.test(message))).toEqual([]);
      expect(networkErrors, 'Unexpected API failures').toEqual([]);
    }
  }, { auto: true }],
});

export { expect };

export async function navigate(page: Page, name: string): Promise<void> {
  const link = page.getByRole('link', { name, exact: true }).first();
  if (!await link.isVisible()) {
    const group = ['Query', 'CVSS', 'Package URL', 'CPE'].includes(name) ? 'Tools'
      : name === 'Match confidence' ? 'Documentation' : 'Administration';
    await page.getByRole('button').filter({ hasText: group }).click();
  }
  await link.click();
}

export async function editJson(container: Page | Locator, value: string): Promise<void> {
  const editor = container.locator('.monaco-editor textarea').first();
  await editor.focus();
  // Monaco chooses shortcuts from the browser's emulated user agent, while
  // Playwright's ControlOrMeta uses the host OS (different on macOS runners).
  const modifier = await editor.page().evaluate(() => navigator.userAgent.includes('Macintosh') ? 'Meta' : 'Control');
  await editor.press(`${modifier}+a`);
  await editor.press('Backspace');
  // Monaco's textarea holds only a window of its model. DOM fill() can leave
  // existing model text behind; insert through its keyboard input instead.
  await editor.page().keyboard.insertText(value);
  await editor.blur();
}

export async function freshSbom(name = `e2e-${randomUUID()}`): Promise<Buffer> {
  const bom = JSON.parse((await document(`${urllib3}/sbom_urllib3_affected.cdx.json`)).toString());
  bom.serialNumber = `urn:uuid:${randomUUID()}`;
  bom.metadata.component.name = name;
  return Buffer.from(JSON.stringify(bom));
}

export async function hostDocument(data: Buffer, owned: OwnedData): Promise<string> {
  if (!process.env.E2E_FIXTURE_DIR) throw new Error('Use npm run test:e2e to start the fixture server');
  const filename = `${randomUUID()}.json`;
  const path = resolve(process.env.E2E_FIXTURE_DIR, filename);
  await writeFile(path, data);
  owned.files.push(path);
  return `${process.env.E2E_FIXTURE_URL}/${filename}`;
}

export async function hostRepository(data: Buffer, owned: OwnedData): Promise<string> {
  const documentURL = await hostDocument(data, owned);
  const id = new URL(documentURL).pathname.slice(1, -'.json'.length);
  const manifest = resolve(process.env.E2E_FIXTURE_DIR!, `${id}.manifest`);
  await writeFile(manifest, `document.json,${createHash('sha256').update(data).digest('hex')},${data.length}\n`);
  owned.files.push(manifest);
  return `${process.env.E2E_FIXTURE_URL}/${id}/`;
}

export async function trackUpload(page: Page, owned: OwnedData, action: () => Promise<unknown>): Promise<string> {
  const pending = page.waitForResponse(response =>
    /\/api\/v3\/upload(?:\/from-url)?$/.test(response.url()) && response.request().method() === 'POST');
  await action();
  const response = await pending;
  expect(response.ok(), await response.text()).toBeTruthy();
  const id = uuid((await response.json()).id);
  owned.sboms.push(id);
  return id;
}
