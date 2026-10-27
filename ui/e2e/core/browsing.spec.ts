import { test, expect, navigate, document, urllib3, openssl, freshSbom, upload } from '../support';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';

test('navigation, direct links, reload, and browser history', async ({ page, seed }) => {
  await page.goto('/');
  await expect(page.getByRole('row').filter({ hasText: 's6-urllib3-affected' })).toBeVisible();
  for (const [name, expected] of [
    ['Advisories', 'Search advisories...'], ['Query', 'Enter identifier value'],
    ['Ingest', 'Ingest Document'], ['Importers', 'Importers'],
    ['Correlation status', 'Correlation status'], ['Provider aliases', 'Provider aliases'],
    ['Options', 'Correlation Options'], ['Match confidence', 'Match confidence'],
  ]) {
    await navigate(page, name);
    if (expected.endsWith('...') || expected === 'Enter identifier value') {
      await expect(page.getByPlaceholder(expected)).toBeVisible();
    } else await expect(page.getByRole('heading', { name: expected, exact: true })).toBeVisible();
  }
  await navigate(page, 'Ingest');
  const direct = page.url();
  await navigate(page, 'SBOMs');
  await page.goBack();
  await expect(page.getByRole('heading', { name: 'Ingest Document' })).toBeVisible();
  await page.goForward();
  await expect(page.getByPlaceholder('Search SBOMs...')).toBeVisible();
  await page.goto(direct);
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Ingest Document' })).toBeVisible();
  await page.goto(`/correlation/${seed.affected}`);
  await expect(page.getByRole('row').filter({ hasText: 'CVE-2023-45803' })).toContainText('Affected');
});

test('SBOM search, empty results, clearing search, and verdict counts', async ({ page, seed }) => {
  await page.goto('/');
  const search = page.getByPlaceholder('Search SBOMs...');
  await search.fill('s6-urllib3-affected');
  await search.press('Tab');
  const row = page.getByRole('row').filter({ hasText: 's6-urllib3-affected' });
  await expect(row).toContainText('Affected');
  await row.click();
  await expect(page).toHaveURL(url => decodeURIComponent(url.pathname).endsWith(`/urn:uuid:${seed.affected}`));
  await navigate(page, 'SBOMs');
  await search.fill('e2e-no-such-sbom');
  await search.press('Tab');
  await expect(page.getByRole('heading', { name: 'No SBOMs found' })).toBeVisible();
  await search.fill('');
  await search.press('Tab');
  await expect(row).toBeVisible();
});

test('advisory search, sorting, and empty results', async ({ page, seed }) => {
  await page.goto('/advisorylist');
  const search = page.getByPlaceholder('Search advisories...');
  await search.fill('GHSA-g4mx-q9vg-27p4');
  await search.press('Tab');
  await expect(page.getByRole('row').filter({ hasText: 'GHSA-g4mx-q9vg-27p4' })).toBeVisible();
  const sorted = page.waitForResponse(r => r.url().includes('/api/v3/advisory?') && new URL(r.url()).searchParams.has('sort'));
  await page.getByRole('columnheader', { name: 'Advisory', exact: true }).getByRole('button').click();
  expect((await sorted).ok()).toBeTruthy();
  await search.fill('e2e-no-such-advisory');
  await search.press('Tab');
  await expect(page.getByRole('heading', { name: 'No advisories found' })).toBeVisible();
  await search.fill('');
  await search.press('Tab');
  await expect(page.getByRole('row').filter({ hasText: 'GHSA-g4mx-q9vg-27p4' })).toBeVisible();
});

for (const [format, key, source] of [
  ['OSV', 'osv', `${urllib3}/osv/GHSA-g4mx-q9vg-27p4.json`],
  ['CVE', 'cve', `${urllib3}/cve/CVE-2023-45803.json`],
  ['CSAF', 'csaf', `${openssl}/vex/CVE-2022-4304.json.xz`],
] as const) {
  test(`${format} advisory detail, source formatting, and download`, async ({ page, seed }) => {
    await page.goto(`/advisory/${seed[key]}`);
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    await expect(page.getByText(format).first()).toBeVisible();
    await page.getByRole('button', { name: 'Source', exact: true }).click();
    await expect(page.locator('.monaco-editor').first()).toBeVisible();
    const formatSwitch = page.getByRole('checkbox', { name: 'Format JSON' });
    await expect(formatSwitch).toBeChecked();
    await formatSwitch.focus();
    await formatSwitch.press('Space');
    await expect(formatSwitch).not.toBeChecked();
    const pending = page.waitForEvent('download');
    await page.getByRole('link', { name: 'Download', exact: true }).click();
    const download = await pending;
    expect(download.suggestedFilename()).toMatch(/\.json$/);
    expect(await readFile((await download.path())!)).toEqual(await document(source));
    await page.getByRole('button', { name: 'Overview', exact: true }).click();
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  });
}

test('SBOM pagination changes the requested offset and visible rows', async ({ page, request, owned, seed }) => {
  // The default page contains ten items; create enough scoped documents to cross it.
  for (let i = 0; i < 12; i++) owned.sboms.push(await upload(request, await freshSbom(`e2e-pagination-${i}`)));
  await page.goto('/');
  await page.getByPlaceholder('Search SBOMs...').fill('e2e-pagination-');
  await page.getByPlaceholder('Search SBOMs...').press('Tab');
  await expect(page.getByRole('row').filter({ hasText: 'e2e-pagination-' })).toHaveCount(10);
  const before = await page.getByRole('row').filter({ hasText: 'e2e-pagination-' }).allTextContents();
  const response = page.waitForResponse(r => r.url().includes('/api/v3/sbom?') && new URL(r.url()).searchParams.get('offset') === '10');
  await page.getByRole('button', { name: /next page/i }).first().click();
  expect((await response).ok()).toBeTruthy();
  await expect(page.getByRole('row').filter({ hasText: 'e2e-pagination-' })).toHaveCount(2);
  expect(await page.getByRole('row').filter({ hasText: 'e2e-pagination-' }).allTextContents()).not.toEqual(before);
});

test('advisory pagination preserves search while advancing the page', async ({ page, request, owned }) => {
  for (let i = 0; i < 12; i++) {
    const advisory = {
      schema_version: '1.7.3', id: `E2E-PAGINATION-${randomUUID()}`,
      modified: '2024-01-01T00:00:00Z', published: '2024-01-01T00:00:00Z',
      summary: `e2e-advisory-pagination-${i}`, affected: [{
        package: { ecosystem: 'PyPI', name: 'e2e-advisory-pagination' },
        ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '1.0' }] }],
      }],
    };
    owned.advisories.push(await upload(request, Buffer.from(JSON.stringify(advisory))));
  }
  await page.goto('/advisorylist');
  const search = page.getByPlaceholder('Search advisories...');
  await search.fill('E2E-PAGINATION-');
  await search.press('Tab');
  const rows = page.getByRole('row').filter({ hasText: 'E2E-PAGINATION-' });
  await expect(rows).toHaveCount(10);
  const pending = page.waitForResponse(response => {
    const url = new URL(response.url());
    return url.pathname === '/api/v3/advisory' && url.searchParams.get('offset') === '10';
  });
  await page.getByRole('button', { name: /next page/i }).first().click();
  const response = await pending;
  expect(response.ok()).toBeTruthy();
  expect(new URL(response.url()).searchParams.get('q')).toBe('E2E-PAGINATION-');
  await expect(rows).toHaveCount(2);
});
