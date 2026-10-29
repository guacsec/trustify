import { test, expect, freshSbom, trackUpload } from '../support';

test('disabled correlation hides navigation and SBOM columns while ingestion works', async ({ page, seed, owned }) => {
  const correlationRequests: string[] = [];
  page.on('request', request => {
    if (request.url().includes('/api/v3/correlation/')) correlationRequests.push(request.url());
  });
  await page.goto('/');
  await expect(page.getByRole('row').filter({ hasText: 's6-urllib3-affected' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Query', exact: true })).toHaveCount(0);
  await expect(page.getByRole('columnheader', { name: 'Verdicts', exact: true })).toHaveCount(0);
  await expect(page.getByRole('columnheader', { name: 'Remediations', exact: true })).toHaveCount(0);
  await page.goto(`/advisory/${seed.csaf}`);
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  await expect(page.getByText('Failed to load advisory')).toHaveCount(0);
  await page.goto('/ingest');
  await page.locator('input[type=file]').setInputFiles({ name: 'no-correlation.json', mimeType: 'application/json', buffer: await freshSbom() });
  await trackUpload(page, owned, () => page.getByRole('button', { name: 'Upload', exact: true }).click());
  await expect(page.getByText('Document ingested: no-correlation.json')).toBeVisible();
  expect(correlationRequests).toEqual([]);
});

for (const path of ['query', 'options', 'provideraliases', 'confidence', 'correlationstatus', 'correlation']) {
  test(`disabled correlation blocks direct ${path} navigation`, async ({ page, seed }) => {
    const correlationRequests: string[] = [];
    page.on('request', request => {
      if (request.url().includes('/api/v3/correlation/')) correlationRequests.push(request.url());
    });
    await page.goto(path === 'correlation' ? `/correlation/${seed.affected}` : `/${path}`);
    await expect(page.getByRole('heading', { name: 'Correlation is disabled on this instance' })).toBeVisible();
    expect(correlationRequests).toEqual([]);
  });
}

test('legacy discovery without a correlation capability fails closed', async ({ page }) => {
  await page.route('**/.well-known/trustify', async route => {
    const response = await route.fetch();
    const discovery = await response.json();
    delete discovery.capabilities;
    await route.fulfill({ response, json: discovery });
  });
  await page.goto('/query');
  await expect(page.getByRole('heading', { name: 'Correlation is disabled on this instance' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Query', exact: true })).toHaveCount(0);
});

test('inspection tools remain available without correlation', async ({ page }) => {
  for (const [tool, title] of [['cvss', 'CVSS'], ['purl', 'Package URL'], ['cpe', 'CPE']]) {
    await page.goto('/tools/' + tool);
    await expect(page.getByRole('heading', { name: title, exact: true })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Query', exact: true })).toHaveCount(0);
  }
});
